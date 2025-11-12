//! CI/CD Integration Helpers (Phase 24)
//!
//! Test infrastructure for continuous integration and deployment:
//! - Test result aggregation and reporting
//! - Code coverage calculation and tracking
//! - Performance benchmarking and regression detection
//! - Test timing analysis and optimization
//! - Failure categorization and triage
//!
//! This module provides helper functions for integrating the QUIC test suite
//! with CI/CD systems (GitHub Actions, GitLab CI, Jenkins, etc.).

const std = @import("std");

const Allocator = std.mem.Allocator;

// =============================================================================
// Test Result Types and Aggregation
// =============================================================================

/// Test execution result
pub const TestResult = enum {
    passed,
    failed,
    skipped,
    timeout,
};

/// Individual test case result
pub const TestCase = struct {
    name: []const u8,
    file: []const u8,
    result: TestResult,
    duration_ms: u64,
    error_message: ?[]const u8 = null,
    stack_trace: ?[]const u8 = null,
};

/// Aggregated test suite results
pub const TestSuiteResults = struct {
    total_tests: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    timeout: usize,
    total_duration_ms: u64,
    timestamp: i64,
};

/// Aggregate test results from multiple test cases
pub fn aggregateResults(test_cases: []const TestCase) TestSuiteResults {
    var results = TestSuiteResults{
        .total_tests = test_cases.len,
        .passed = 0,
        .failed = 0,
        .skipped = 0,
        .timeout = 0,
        .total_duration_ms = 0,
        .timestamp = std.time.milliTimestamp(),
    };

    for (test_cases) |test_case| {
        switch (test_case.result) {
            .passed => results.passed += 1,
            .failed => results.failed += 1,
            .skipped => results.skipped += 1,
            .timeout => results.timeout += 1,
        }
        results.total_duration_ms += test_case.duration_ms;
    }

    return results;
}

/// Calculate pass rate percentage
pub fn calculatePassRate(results: TestSuiteResults) f64 {
    if (results.total_tests == 0) return 0.0;

    const executed = results.total_tests - results.skipped;
    if (executed == 0) return 0.0;

    return @as(f64, @floatFromInt(results.passed)) /
        @as(f64, @floatFromInt(executed)) * 100.0;
}

/// Find slowest tests
pub fn findSlowestTests(
    allocator: Allocator,
    test_cases: []const TestCase,
    limit: usize,
) !std.ArrayList(TestCase) {
    var slowest = std.ArrayList(TestCase){};
    errdefer slowest.deinit(allocator);

    // TODO: Sort test cases by duration and return top N
    // For now, return empty list
    _ = test_cases;
    _ = limit;

    return slowest;
}

// =============================================================================
// Code Coverage Types and Calculation
// =============================================================================

/// Coverage metric for a source file
pub const FileCoverage = struct {
    file_path: []const u8,
    total_lines: usize,
    covered_lines: usize,
    coverage_percentage: f64,
};

/// Aggregated coverage metrics
pub const CoverageMetrics = struct {
    total_files: usize,
    total_lines: usize,
    covered_lines: usize,
    overall_coverage: f64,
    file_coverage: []const FileCoverage,
};

/// Calculate coverage percentage for a file
pub fn calculateFileCoverage(total_lines: usize, covered_lines: usize) f64 {
    if (total_lines == 0) return 0.0;

    return @as(f64, @floatFromInt(covered_lines)) /
        @as(f64, @floatFromInt(total_lines)) * 100.0;
}

/// Aggregate coverage metrics from file coverage data
pub fn aggregateCoverage(file_coverage: []const FileCoverage) CoverageMetrics {
    var metrics = CoverageMetrics{
        .total_files = file_coverage.len,
        .total_lines = 0,
        .covered_lines = 0,
        .overall_coverage = 0.0,
        .file_coverage = file_coverage,
    };

    for (file_coverage) |coverage| {
        metrics.total_lines += coverage.total_lines;
        metrics.covered_lines += coverage.covered_lines;
    }

    metrics.overall_coverage = calculateFileCoverage(
        metrics.total_lines,
        metrics.covered_lines,
    );

    return metrics;
}

/// Check if coverage meets minimum threshold
pub fn meetsCoverageThreshold(
    metrics: CoverageMetrics,
    threshold: f64,
) bool {
    return metrics.overall_coverage >= threshold;
}

// =============================================================================
// Performance Benchmarking Types and Analysis
// =============================================================================

/// Performance benchmark result
pub const BenchmarkResult = struct {
    name: []const u8,
    iterations: usize,
    total_time_ns: u64,
    avg_time_ns: u64,
    min_time_ns: u64,
    max_time_ns: u64,
    std_dev_ns: u64,
};

/// Performance regression detection
pub const RegressionResult = struct {
    benchmark_name: []const u8,
    baseline_avg_ns: u64,
    current_avg_ns: u64,
    change_percentage: f64,
    is_regression: bool,
};

/// Calculate average time from benchmark
pub fn calculateBenchmarkStats(
    iterations: usize,
    total_time_ns: u64,
) struct { avg: u64, per_iteration: u64 } {
    if (iterations == 0) return .{ .avg = 0, .per_iteration = 0 };

    const avg = total_time_ns / iterations;
    return .{ .avg = avg, .per_iteration = avg };
}

/// Detect performance regression
pub fn detectRegression(
    baseline_avg_ns: u64,
    current_avg_ns: u64,
    threshold_percentage: f64,
) RegressionResult {
    const change = @as(f64, @floatFromInt(current_avg_ns)) -
        @as(f64, @floatFromInt(baseline_avg_ns));
    const change_percentage = (change / @as(f64, @floatFromInt(baseline_avg_ns))) * 100.0;

    return RegressionResult{
        .benchmark_name = "",
        .baseline_avg_ns = baseline_avg_ns,
        .current_avg_ns = current_avg_ns,
        .change_percentage = change_percentage,
        .is_regression = change_percentage > threshold_percentage,
    };
}

/// Calculate throughput from benchmark (operations per second)
pub fn calculateThroughput(iterations: usize, total_time_ns: u64) f64 {
    if (total_time_ns == 0) return 0.0;

    const seconds = @as(f64, @floatFromInt(total_time_ns)) / 1_000_000_000.0;
    return @as(f64, @floatFromInt(iterations)) / seconds;
}

// =============================================================================
// Test Timing Analysis
// =============================================================================

/// Test timing statistics
pub const TimingStats = struct {
    total_tests: usize,
    total_duration_ms: u64,
    avg_duration_ms: f64,
    median_duration_ms: u64,
    p95_duration_ms: u64,
    p99_duration_ms: u64,
};

/// Calculate timing statistics from test cases
pub fn calculateTimingStats(test_cases: []const TestCase) TimingStats {
    var stats = TimingStats{
        .total_tests = test_cases.len,
        .total_duration_ms = 0,
        .avg_duration_ms = 0.0,
        .median_duration_ms = 0,
        .p95_duration_ms = 0,
        .p99_duration_ms = 0,
    };

    if (test_cases.len == 0) return stats;

    // Calculate total and average
    for (test_cases) |test_case| {
        stats.total_duration_ms += test_case.duration_ms;
    }

    stats.avg_duration_ms = @as(f64, @floatFromInt(stats.total_duration_ms)) /
        @as(f64, @floatFromInt(test_cases.len));

    // TODO: Calculate median, p95, p99 (requires sorting)
    // For now, use average as approximation
    stats.median_duration_ms = @intFromFloat(stats.avg_duration_ms);
    stats.p95_duration_ms = @intFromFloat(stats.avg_duration_ms * 1.5);
    stats.p99_duration_ms = @intFromFloat(stats.avg_duration_ms * 2.0);

    return stats;
}

/// Identify tests that exceed time budget
pub fn findSlowTests(
    allocator: Allocator,
    test_cases: []const TestCase,
    threshold_ms: u64,
) !std.ArrayList(TestCase) {
    var slow_tests = std.ArrayList(TestCase){};
    errdefer slow_tests.deinit(allocator);

    for (test_cases) |test_case| {
        if (test_case.duration_ms > threshold_ms) {
            try slow_tests.append(allocator, test_case);
        }
    }

    return slow_tests;
}

// =============================================================================
// Failure Categorization and Triage
// =============================================================================

/// Failure category for triage
pub const FailureCategory = enum {
    assertion_failure,
    timeout,
    segmentation_fault,
    memory_leak,
    network_error,
    tls_error,
    protocol_violation,
    unknown,
};

/// Categorized test failure
pub const CategorizedFailure = struct {
    test_case: TestCase,
    category: FailureCategory,
    priority: u8, // 1-5, where 5 is highest priority
};

/// Categorize failure based on error message
pub fn categorizeFailure(test_case: TestCase) CategorizedFailure {
    var category = FailureCategory.unknown;
    var priority: u8 = 3; // Default medium priority

    if (test_case.result == .timeout) {
        category = .timeout;
        priority = 4; // High priority
    } else if (test_case.error_message) |msg| {
        if (std.mem.indexOf(u8, msg, "assertion") != null or
            std.mem.indexOf(u8, msg, "expected") != null)
        {
            category = .assertion_failure;
            priority = 3;
        } else if (std.mem.indexOf(u8, msg, "segmentation") != null or
            std.mem.indexOf(u8, msg, "SIGSEGV") != null)
        {
            category = .segmentation_fault;
            priority = 5; // Critical
        } else if (std.mem.indexOf(u8, msg, "leak") != null) {
            category = .memory_leak;
            priority = 4;
        } else if (std.mem.indexOf(u8, msg, "network") != null or
            std.mem.indexOf(u8, msg, "socket") != null)
        {
            category = .network_error;
            priority = 2;
        } else if (std.mem.indexOf(u8, msg, "TLS") != null or
            std.mem.indexOf(u8, msg, "handshake") != null)
        {
            category = .tls_error;
            priority = 3;
        } else if (std.mem.indexOf(u8, msg, "protocol") != null or
            std.mem.indexOf(u8, msg, "RFC") != null)
        {
            category = .protocol_violation;
            priority = 4;
        }
    }

    return CategorizedFailure{
        .test_case = test_case,
        .category = category,
        .priority = priority,
    };
}

/// Group failures by category
pub fn groupFailuresByCategory(
    allocator: Allocator,
    failures: []const CategorizedFailure,
) !std.AutoHashMap(FailureCategory, usize) {
    var groups = std.AutoHashMap(FailureCategory, usize).init(allocator);
    errdefer groups.deinit();

    for (failures) |failure| {
        const count = groups.get(failure.category) orelse 0;
        try groups.put(failure.category, count + 1);
    }

    return groups;
}

// =============================================================================
// Report Generation
// =============================================================================

/// Report format
pub const ReportFormat = enum {
    json,
    xml,
    junit,
    html,
    markdown,
};

/// Generate test report in specified format
/// TODO: Implement actual report generation for each format
pub fn generateReport(
    allocator: Allocator,
    results: TestSuiteResults,
    format: ReportFormat,
) ![]const u8 {
    _ = allocator;
    _ = results;

    return switch (format) {
        .json => "{ \"status\": \"not implemented\" }",
        .xml => "<result>not implemented</result>",
        .junit => "<testsuite><testcase/></testsuite>",
        .html => "<html><body>not implemented</body></html>",
        .markdown => "# Test Results\nNot implemented",
    };
}

/// Generate coverage report
pub fn generateCoverageReport(
    allocator: Allocator,
    metrics: CoverageMetrics,
    format: ReportFormat,
) ![]const u8 {
    _ = allocator;
    _ = metrics;
    _ = format;

    return "Coverage report not implemented";
}

// =============================================================================
// CI/CD Integration Helpers
// =============================================================================

/// CI environment detection
pub const CiEnvironment = enum {
    github_actions,
    gitlab_ci,
    jenkins,
    circleci,
    travis_ci,
    azure_pipelines,
    local,
};

/// Detect current CI environment from environment variables
pub fn detectCiEnvironment() CiEnvironment {
    if (std.process.getEnvVarOwned(
        std.heap.page_allocator,
        "GITHUB_ACTIONS",
    )) |_| {
        return .github_actions;
    } else |_| {}

    if (std.process.getEnvVarOwned(
        std.heap.page_allocator,
        "GITLAB_CI",
    )) |_| {
        return .gitlab_ci;
    } else |_| {}

    if (std.process.getEnvVarOwned(
        std.heap.page_allocator,
        "JENKINS_HOME",
    )) |_| {
        return .jenkins;
    } else |_| {}

    return .local;
}

/// Exit with CI-appropriate status code
pub fn exitWithStatus(results: TestSuiteResults) void {
    const exit_code: u8 = if (results.failed > 0 or results.timeout > 0)
        1
    else
        0;

    std.process.exit(exit_code);
}

// =============================================================================
// Unit Tests
// =============================================================================

test "aggregateResults - calculate totals" {
    const test_cases = [_]TestCase{
        .{
            .name = "test1",
            .file = "file1.zig",
            .result = .passed,
            .duration_ms = 100,
        },
        .{
            .name = "test2",
            .file = "file1.zig",
            .result = .failed,
            .duration_ms = 50,
        },
        .{
            .name = "test3",
            .file = "file2.zig",
            .result = .skipped,
            .duration_ms = 0,
        },
    };

    const results = aggregateResults(&test_cases);

    try std.testing.expectEqual(@as(usize, 3), results.total_tests);
    try std.testing.expectEqual(@as(usize, 1), results.passed);
    try std.testing.expectEqual(@as(usize, 1), results.failed);
    try std.testing.expectEqual(@as(usize, 1), results.skipped);
    try std.testing.expectEqual(@as(u64, 150), results.total_duration_ms);
}

test "calculatePassRate - percentage calculation" {
    const results = TestSuiteResults{
        .total_tests = 10,
        .passed = 8,
        .failed = 1,
        .skipped = 1,
        .timeout = 0,
        .total_duration_ms = 1000,
        .timestamp = 0,
    };

    const pass_rate = calculatePassRate(results);

    // 8 passed out of 9 executed (1 skipped) = 88.89%
    try std.testing.expectApproxEqAbs(88.89, pass_rate, 0.01);
}

test "calculateFileCoverage - percentage" {
    const coverage = calculateFileCoverage(100, 80);
    try std.testing.expectApproxEqAbs(80.0, coverage, 0.01);
}

test "aggregateCoverage - total metrics" {
    const file_coverage = [_]FileCoverage{
        .{
            .file_path = "file1.zig",
            .total_lines = 100,
            .covered_lines = 80,
            .coverage_percentage = 80.0,
        },
        .{
            .file_path = "file2.zig",
            .total_lines = 50,
            .covered_lines = 40,
            .coverage_percentage = 80.0,
        },
    };

    const metrics = aggregateCoverage(&file_coverage);

    try std.testing.expectEqual(@as(usize, 2), metrics.total_files);
    try std.testing.expectEqual(@as(usize, 150), metrics.total_lines);
    try std.testing.expectEqual(@as(usize, 120), metrics.covered_lines);
    try std.testing.expectApproxEqAbs(80.0, metrics.overall_coverage, 0.01);
}

test "meetsCoverageThreshold - threshold check" {
    const metrics = CoverageMetrics{
        .total_files = 1,
        .total_lines = 100,
        .covered_lines = 85,
        .overall_coverage = 85.0,
        .file_coverage = &[_]FileCoverage{},
    };

    try std.testing.expect(meetsCoverageThreshold(metrics, 80.0));
    try std.testing.expect(!meetsCoverageThreshold(metrics, 90.0));
}

test "detectRegression - performance change" {
    const regression = detectRegression(1000, 1200, 10.0);

    try std.testing.expectEqual(@as(u64, 1000), regression.baseline_avg_ns);
    try std.testing.expectEqual(@as(u64, 1200), regression.current_avg_ns);
    try std.testing.expectApproxEqAbs(20.0, regression.change_percentage, 0.01);
    try std.testing.expect(regression.is_regression);

    // No regression
    const no_regression = detectRegression(1000, 1050, 10.0);
    try std.testing.expect(!no_regression.is_regression);
}

test "calculateThroughput - ops per second" {
    const throughput = calculateThroughput(1000, 1_000_000_000); // 1 second
    try std.testing.expectApproxEqAbs(1000.0, throughput, 0.01);
}

test "calculateTimingStats - statistics" {
    const test_cases = [_]TestCase{
        .{
            .name = "test1",
            .file = "file.zig",
            .result = .passed,
            .duration_ms = 100,
        },
        .{
            .name = "test2",
            .file = "file.zig",
            .result = .passed,
            .duration_ms = 200,
        },
        .{
            .name = "test3",
            .file = "file.zig",
            .result = .passed,
            .duration_ms = 150,
        },
    };

    const stats = calculateTimingStats(&test_cases);

    try std.testing.expectEqual(@as(usize, 3), stats.total_tests);
    try std.testing.expectEqual(@as(u64, 450), stats.total_duration_ms);
    try std.testing.expectApproxEqAbs(150.0, stats.avg_duration_ms, 0.01);
}

test "categorizeFailure - assertion" {
    const test_case = TestCase{
        .name = "test1",
        .file = "file.zig",
        .result = .failed,
        .duration_ms = 100,
        .error_message = "assertion failed: expected true",
    };

    const failure = categorizeFailure(test_case);

    try std.testing.expectEqual(FailureCategory.assertion_failure, failure.category);
    try std.testing.expectEqual(@as(u8, 3), failure.priority);
}

test "categorizeFailure - timeout" {
    const test_case = TestCase{
        .name = "test1",
        .file = "file.zig",
        .result = .timeout,
        .duration_ms = 30000,
    };

    const failure = categorizeFailure(test_case);

    try std.testing.expectEqual(FailureCategory.timeout, failure.category);
    try std.testing.expectEqual(@as(u8, 4), failure.priority);
}

test "detectCiEnvironment - local by default" {
    const env = detectCiEnvironment();
    // This will be .local unless running in actual CI
    _ = env; // Just verify it doesn't crash
}
