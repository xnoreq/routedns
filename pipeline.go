package rdns

import (
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Defines how long to wait for a response from the resolver if no other timeout is given.
const defaultQueryTimeout = 2 * time.Second

// Tear down an upstream connection if nothing has been received for this long.
const idleTimeout = 10 * time.Second

// Pipeline is a DNS client that is able to use pipelining for multiple requests over
// one connection, handle out-of-order responses and deals with disconnects
// gracefully. It opens a single connection on demand and uses it for all queries.
// It can manage UDP, TCP, DNS-over-TLS, and DNS-over-DTLS connections.
type Pipeline struct {
	addr     string
	client   DNSDialer
	requests chan *request
	inFlight inFlightQueue
	metrics  *ListenerMetrics
	timeout  time.Duration
	reqsSema chan struct{}
}

// DNSDialer is an abstraction for a dns.Client that returns a *dns.Conn.
type DNSDialer interface {
	Dial(address string) (*dns.Conn, error)
}

// NewPipeline returns an initialized (and running) DNS connection manager.
func NewPipeline(id string, addr string, client DNSDialer, timeout time.Duration) *Pipeline {
	if timeout == 0 {
		timeout = defaultQueryTimeout
	}
	c := &Pipeline{
		addr:     addr,
		client:   client,
		requests: make(chan *request),
		inFlight: newInFlightQueue(),
		metrics:  NewListenerMetrics("client", id),
		timeout:  timeout,
		reqsSema: make(chan struct{}, math.MaxUint16-1), // limits concurrent requests
	}
	go c.start()
	return c
}

// Resolve a single query using this connection.
func (p *Pipeline) Resolve(q *dns.Msg) (*dns.Msg, error) {
	timeout := time.NewTimer(p.timeout)
	defer timeout.Stop()

	// Acquire semaphore token or timeout waiting for a free slot
	select {
	case p.reqsSema <- struct{}{}:
	case <-timeout.C:
		p.metrics.err.Add("querytimeout", 1)
		return nil, QueryTimeoutError{q}
	}

	// Ensure token is released when Resolve exits
	defer func() { <-p.reqsSema }()

	// Queue up the request or time out
	r := newRequest(q)
	select {
	case p.requests <- r:
	case <-timeout.C:
		p.metrics.err.Add("querytimeout", 1)
		return nil, QueryTimeoutError{q}
	}

	// Wait for the request to complete or time out
	select {
	case <-r.done:
		return r.a, r.err
	case <-timeout.C:
		p.inFlight.delete(r)
		p.metrics.err.Add("querytimeout", 1)
		return nil, QueryTimeoutError{q}
	}
}

// Starts a loop that will wait for queries and open an upstream connection on-demand, writing queries
// and reading answers concurrently using the same connection. It also handles errors like idle
// close from upstream.
func (p *Pipeline) start() {
	var wg sync.WaitGroup
	log := Log.With("addr", p.addr)

	var pendingReq *request
	for {
		// Acquire a request: reuse a pending retry request or wait for a new one from p.requests
		var ok bool
		if pendingReq == nil {
			pendingReq, ok = <-p.requests
			if !ok {
				break
			}
		}

		req := pendingReq
		pendingReq = nil

		done := make(chan struct{})
		// Lazy connection. Only open a real connection if there's a request
		log.Debug("opening connection")
		conn, err := p.client.Dial(p.addr)
		if err != nil {
			p.metrics.err.Add("open", 1)
			log.Warn("failed to open connection", "error", err)
			req.markDone(nil, err)

			// drain and fail queued requests
		DrainLoop:
			for {
				select {
				case req, ok = <-p.requests:
					if !ok {
						break DrainLoop
					}
					req.markDone(nil, err)
				default:
					break DrainLoop
				}
			}
			continue
		}

		wg.Add(2)

		go func() { // writer
			defer wg.Done()
			defer conn.Close() // should wake up the reader as well

			w := func(req *request, isFresh bool) bool {
				query := p.inFlight.add(req)
				log.With("qname", qName(query)).Debug("sending query")
				p.metrics.query.Add(1)
				if err := conn.WriteMsg(query); err != nil {
					// Take the request back out of the in-flight queue before
					// completing it. The reader matches responses by ID and
					// completes whatever request it finds there; completing a
					// request twice would panic on the double close of its
					// done channel. Whoever removes it from the queue owns it.
					if p.inFlight.get(query) != nil {
						if isFresh {
							req.markDone(nil, err) // fail the request
						} else {
							// Failed on a reused connection (e.g., idle connection closed by upstream);
							// hand back for retry on a fresh connection
							pendingReq = req
						}
					}
					p.metrics.err.Add("send_query", 1)
					log.With("qname", qName(query)).Debug("failed sending query",
						"error", err)
					return false
				}

				return true
			}

			if ok := w(req, true); !ok { // initial request
				return
			}

			for {
				select {
				case req := <-p.requests:
					if ok = w(req, false); !ok {
						return
					}
				case <-done: // the reader ran into an error and we want to stop using this connection
					return
				}
			}
		}()

		go func() { // reader
			defer wg.Done()
			defer close(done) // tell the writer to not use this connection anymore

			for {
				// Set the idle deadline on the reader, not the writer since when using UDP "connections",
				// a network topology change wouldn't be noticed. Putting the idle timeout here ensures
				// a reconnect in that case as well. This does create a very slight race however if the
				// sender is using the connection right at the time of the timeout in the receiver.
				_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
				a, err := conn.ReadMsg()
				if err != nil {
					switch e := err.(type) {
					case net.Error:
						if e.Timeout() {
							log.Debug("connection terminated by idle timeout")
						} else {
							p.metrics.err.Add("server_term", 1)
							log.Debug("connection terminated by server")
						}
						return
					default:
						if err == io.EOF {
							p.metrics.err.Add("server_eof", 1)
							log.Debug("connection terminated by server")
							return
						}
						// It's possible the response can't be correctly parsed, but we do have a response.
						// In this case, return it and carry on, don't terminate the connection because we
						// got a bad packet (like a truncated one for example).
						if a == nil {
							p.metrics.err.Add("read", 1)
							log.Warn("read failed", "error", err)
							return
						}
						log.Warn("failed to read response", "error", err, "qname", qName(a))
					}
				}
				req := p.inFlight.get(a) // match the answer to an in-flight query
				if req == nil {
					p.metrics.err.Add("unexpected_a", 1)
					log.With("qname", qName(a)).Warn("unexpected answer received, ignoring")
					continue
				}
				p.metrics.response.Add(rCode(a), 1)
				req.markDone(a, nil)
				ql := p.inFlight.maxQueueLen()
				if ql > p.metrics.maxQueueLen.Value() {
					p.metrics.maxQueueLen.Set(ql)
				}
			}
		}()

		// wait for both, sender and receiver to terminate before trying to reconnect
		wg.Wait()
		p.inFlight.drain(errors.New("upstream connection closed with request in flight"))
	}
}

// Request received from a client. It also contains the response and a channel that is
// closed when the request is done.
type request struct {
	q, a *dns.Msg
	id   uint16
	err  error
	done chan struct{}
}

func newRequest(q *dns.Msg) *request {
	return &request{
		q:    q,
		done: make(chan struct{}),
	}
}

// Mark the request as complete.
func (r *request) markDone(a *dns.Msg, err error) {
	if a != nil {
		a.Id = r.q.Id // Fix the query ID in the answer to match the query
	}
	r.a = a
	r.err = err
	close(r.done)
}

// Queue to manage requests that are in flight. Used to asynchronously match received
// responses with their requests.
type inFlightQueue struct {
	requests map[uint16]*request
	mu       sync.Mutex
	maxLen   int
}

func newInFlightQueue() inFlightQueue {
	return inFlightQueue{
		requests: make(map[uint16]*request),
	}
}

// Add a request to the queue and return an updated DNS query with a new ID. The ID needs
// to be unique per connection, and we could be receiving multiple queries with the same
// ID. So pick a random ID that isn't currently in flight, use that in the query upstream,
// then map it back to the request and replace the ID with the original one.
func (q *inFlightQueue) add(r *request) *dns.Msg {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.requests) >= math.MaxUint16-1 {
		panic("inFlightQueue len exceeding 2^16-1")
	}
	id := dns.Id()
	for {
		if id == 0 { // avoid default uint16 value
			id++
		}
		if _, inUse := q.requests[id]; !inUse {
			break
		}
		id++
	}
	r.id = id
	q.requests[id] = r
	query := r.q.Copy()
	query.Id = id
	if len(q.requests) > q.maxLen {
		q.maxLen = len(q.requests)
	}
	return query
}

// Returns the request for a given query ID, or nil if the request isn't in the queue
// or the answer was not valid. The returned request is removed from the queue.
func (q *inFlightQueue) get(a *dns.Msg) *request {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := a.Id
	r, ok := q.requests[id]
	if !ok {
		return nil
	}
	if err := validateResponseQuestion(r.q, a); err != nil {
		return nil
	}
	delete(q.requests, id)
	return r
}

// Removes a request from the queue if it is still present. Safe to call when the
// request was never added or was already removed.
func (q *inFlightQueue) delete(r *request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.requests[r.id] == r {
		delete(q.requests, r.id)
	}
}

// Fails all queued requests with err and clears the queue.
func (q *inFlightQueue) drain(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, r := range q.requests {
		r.markDone(nil, err)
	}
	clear(q.requests)
}

func (q *inFlightQueue) maxQueueLen() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return int64(q.maxLen)
}
