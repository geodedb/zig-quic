const std = @import("std");

test "ArrayList with allocator tracking" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    
    // If we need to track the allocator, we need to store it separately
    var list = std.ArrayList(u8){};
    defer list.deinit(alloc);
    
    // Or use a wrapper struct
    const ListWithAlloc = struct {
        list: std.ArrayList(u8),
        allocator: std.mem.Allocator,
        
        fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .list = std.ArrayList(u8){},
                .allocator = allocator,
            };
        }
        
        fn deinit(self: *@This()) void {
            self.list.deinit(self.allocator);
        }
    };
    
    var list2 = ListWithAlloc.init(alloc);
    defer list2.deinit();
    
    try list2.list.append(list2.allocator, 42);
    try std.testing.expectEqual(@as(usize, 1), list2.list.items.len);
}
