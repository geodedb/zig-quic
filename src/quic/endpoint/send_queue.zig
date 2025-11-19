//! Asynchronous send queue for non-blocking packet transmission.
//!
//! This module implements an async send queue similar to quic-go's architecture,
//! decoupling packet assembly from socket I/O to prevent bidirectional streaming deadlocks.
//!
//! Architecture:
//! - Main thread: Assembles packets and enqueues them (non-blocking)
//! - Sender thread: Dequeues packets and writes to socket (blocking sendto is OK here)
//! - Bounded buffer: Capacity 8-16 to apply backpressure
//!
//! Reference: @forks/quic-go/send_queue.go

const std = @import("std");
const posix = std.posix;
const conn_mod = @import("quic_conn");
const io = @import("endpoint_io");

/// A packet job to be sent.
const SendJob = struct {
    data: []u8,  // Owned by SendQueue, will be freed after send
    peer: conn_mod.SockAddr,
    allocator: std.mem.Allocator,

    fn deinit(self: *SendJob) void {
        self.allocator.free(self.data);
    }
};

/// Async send queue with bounded buffer.
/// Prevents main event loop from blocking on socket writes.
pub const SendQueue = struct {
    /// Ring buffer for send jobs (bounded capacity)
    jobs: std.fifo.LinearFifo(SendJob, .Dynamic),
    /// Mutex to protect jobs queue
    mutex: std.Thread.Mutex = .{},
    /// Condition variable to signal sender thread
    cond_has_work: std.Thread.Condition = .{},
    /// Condition variable to signal space available
    cond_space_available: std.Thread.Condition = .{},
    /// Maximum capacity of the send queue
    capacity: usize,
    /// Socket file descriptor for sending
    sock_fd: posix.socket_t,
    /// Thread handle for sender thread
    sender_thread: ?std.Thread = null,
    /// Flag to signal shutdown
    shutdown: bool = false,
    /// Allocator for jobs and queue
    allocator: std.mem.Allocator,

    /// Initialize send queue with bounded capacity.
    /// Capacity should be 8-16 packets (quic-go uses 8).
    pub fn init(allocator: std.mem.Allocator, sock_fd: posix.socket_t, capacity: usize) !*SendQueue {
        const self = try allocator.create(SendQueue);
        self.* = SendQueue{
            .jobs = std.fifo.LinearFifo(SendJob, .Dynamic).init(allocator),
            .capacity = capacity,
            .sock_fd = sock_fd,
            .allocator = allocator,
        };
        return self;
    }

    /// Start the sender thread.
    pub fn start(self: *SendQueue) !void {
        self.sender_thread = try std.Thread.spawn(.{}, senderThreadFn, .{self});
    }

    /// Stop the sender thread and clean up.
    pub fn deinit(self: *SendQueue) void {
        // Signal shutdown
        self.mutex.lock();
        self.shutdown = true;
        self.cond_has_work.signal();
        self.mutex.unlock();

        // Wait for sender thread to exit
        if (self.sender_thread) |thread| {
            thread.join();
        }

        // Free any remaining jobs
        while (self.jobs.readItem()) |*job| {
            job.deinit();
        }

        self.jobs.deinit();
        self.allocator.destroy(self);
    }

    /// Check if the send queue would block (is full).
    /// Returns true if queue is at capacity.
    pub fn wouldBlock(self: *SendQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.jobs.count >= self.capacity;
    }

    /// Enqueue a packet for sending (non-blocking if space available).
    /// Returns error.WouldBlock if queue is full.
    /// Takes ownership of data - caller must not free it.
    pub fn send(self: *SendQueue, peer: conn_mod.SockAddr, data: []u8, allocator: std.mem.Allocator) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if queue is full
        if (self.jobs.count >= self.capacity) {
            return error.WouldBlock;
        }

        // Enqueue the job
        try self.jobs.writeItem(SendJob{
            .data = data,
            .peer = peer,
            .allocator = allocator,
        });

        // Signal sender thread that work is available
        self.cond_has_work.signal();
    }

    /// Sender thread function - runs in background.
    /// Continuously dequeues and sends packets until shutdown.
    fn senderThreadFn(self: *SendQueue) void {
        while (true) {
            var job: ?SendJob = null;

            // Dequeue a job (blocking if queue is empty)
            {
                self.mutex.lock();
                defer self.mutex.unlock();

                // Wait for work or shutdown
                while (self.jobs.count == 0 and !self.shutdown) {
                    self.cond_has_work.wait(&self.mutex);
                }

                // Check shutdown
                if (self.shutdown and self.jobs.count == 0) {
                    return;
                }

                // Dequeue job
                job = self.jobs.readItem();
            }

            // Send the packet (outside mutex - blocking is OK here)
            if (job) |*j| {
                // Call sendto - blocking is OK in sender thread
                _ = io.sendTo(self.sock_fd, j.peer, j.data) catch |err| {
                    std.debug.print("[SendQueue] sendto failed: {}\n", .{err});
                };

                // Free the job
                j.deinit();

                // Signal that space is now available
                self.mutex.lock();
                self.cond_space_available.signal();
                self.mutex.unlock();
            }
        }
    }

    /// Wait until space is available in the queue (blocking).
    /// Used by the event loop to apply backpressure.
    pub fn waitForSpace(self: *SendQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.jobs.count >= self.capacity and !self.shutdown) {
            self.cond_space_available.wait(&self.mutex);
        }
    }
};
