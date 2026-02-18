#!/usr/bin/env python3

import time
import math
import argparse
import ctypes
import os
from ctypes import c_int, c_uint32, c_uint64, c_void_p, POINTER

libc = ctypes.CDLL("libc.so.6", use_errno=True)

BPF_MAP_UPDATE_ELEM = 2
BPF_ANY = 0

def bpf_obj_get(pathname):
    """Open a pinned BPF object and return its file descriptor"""
    BPF_OBJ_GET = 7
    
    class bpf_attr_obj_get(ctypes.Structure):
        _fields_ = [
            ("pathname", c_uint64),
            ("bpf_fd", c_uint32),
            ("file_flags", c_uint32),
        ]
    
    path_bytes = pathname.encode('utf-8') + b'\0'
    path_buf = ctypes.create_string_buffer(path_bytes)
    
    attr = bpf_attr_obj_get()
    attr.pathname = ctypes.cast(path_buf, c_void_p).value
    attr.bpf_fd = 0
    attr.file_flags = 0
    
    fd = libc.syscall(321, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open pinned BPF map {pathname}: {os.strerror(errno)}")
    
    return fd

def bpf_map_update(map_fd, key, value):
    """Update BPF map element"""
    class bpf_attr_map_elem(ctypes.Structure):
        _fields_ = [
            ("map_fd", c_uint32),
            ("_pad1", c_uint32),
            ("key", c_uint64),
            ("value", c_uint64),
            ("flags", c_uint64),
        ]
    
    attr = bpf_attr_map_elem()
    attr.map_fd = map_fd
    attr.key = ctypes.cast(ctypes.byref(key), c_void_p).value
    attr.value = ctypes.cast(ctypes.byref(value), c_void_p).value
    attr.flags = BPF_ANY
    
    ret = libc.syscall(321, BPF_MAP_UPDATE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to update BPF map: {os.strerror(errno)}")

class BPFMap:
    """Simple wrapper for pinned BPF map access"""
    def __init__(self, path):
        self.fd = bpf_obj_get(path)
        self.path = path
    
    def __setitem__(self, key, value):
        if not isinstance(key, c_uint32):
            key = c_uint32(key)
        if not isinstance(value, c_uint32):
            value = c_uint32(value)
        bpf_map_update(self.fd, key, value)
    
    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

def circular_path(center_x, center_y, radius, duration_seconds, update_hz):
    total_updates = int(duration_seconds * update_hz)
    
    if radius == 0:
        for i in range(total_updates):
            t = (i % total_updates) / total_updates
            if t < 0.5:
                progress = t * 2
            else:
                progress = 2 - t * 2
            
            x = int(10 + progress * 980)
            y = int(10 + progress * 980)
            
            x = max(0, min(999, x))
            y = max(0, min(999, y))
            
            yield (x, y)
    else:
        for i in range(total_updates):
            angle = (2 * math.pi * i) / total_updates
            x = int(center_x + radius * math.cos(angle))
            y = int(center_y + radius * math.sin(angle))
            
            x = max(0, min(999, x))
            y = max(0, min(999, y))
            
            yield (x, y)

def update_camera_modes(camera_map, robot_coords_map, x, y):
    """
    Update camera filtering modes based on robot position
    Directly updates BPF maps from userspace
    """
    horizontal_camera = min(49, y // 20)
    vertical_camera = 50 + min(49, x // 20)
    
    # Update all 100 cameras
    MODE_OFF = 0
    MODE_DROP_P = 1
    
    for camera_id in range(100):
        if camera_id == horizontal_camera or camera_id == vertical_camera:
            camera_map[camera_id] = MODE_OFF
        else:
            camera_map[camera_id] = MODE_DROP_P
    
    robot_coords_map[0] = x
    robot_coords_map[1] = y

def main():
    parser = argparse.ArgumentParser(description='Robot simulator with direct BPF map updates')
    parser.add_argument('--center-x', type=int, default=500, help='Circle center X (default: 500)')
    parser.add_argument('--center-y', type=int, default=500, help='Circle center Y (default: 500)')
    parser.add_argument('--radius', type=int, default=400, help='Circle radius (default: 400)')
    parser.add_argument('--duration', type=int, default=60, help='Duration for one round in seconds (default: 60)')
    parser.add_argument('--update-hz', type=int, default=10, help='Position update frequency in Hz (default: 10)')
    parser.add_argument('--loops', type=int, default=1, help='Number of complete loops (default: 1, 0=infinite)')
    parser.add_argument('--map-path', default='/sys/fs/bpf/xdp_pipeline/camera_filtering_mode',
                        help='Path to camera_filtering_mode BPF map')
    parser.add_argument('--coords-map-path', default='/sys/fs/bpf/xdp_pipeline/robot_coords_debug',
                        help='Path to robot_coords_debug BPF map')
    
    args = parser.parse_args()
    
    print(f"Robot Simulator Starting (Direct BPF Map Updates)")
    print(f"Camera filtering map: {args.map_path}")
    print(f"Robot coords map: {args.coords_map_path}")
    print(f"Circular path: center=({args.center_x}, {args.center_y}), radius={args.radius}")
    print(f"Duration: {args.duration} seconds/round")
    print(f"Update rate: {args.update_hz} Hz")
    print(f"Loops: {'infinite' if args.loops == 0 else args.loops}")
    print()
    
    try:
        camera_map = BPFMap(args.map_path)
        robot_coords_map = BPFMap(args.coords_map_path)
        print(f"Successfully opened BPF maps")
        print(f"Camera map FD: {camera_map.fd}")
        print(f"Robot coords map FD: {robot_coords_map.fd}")
    except Exception as e:
        print(f"Failed to open BPF maps: {e}")
        print(f"Make sure XDP programs are loaded and maps are pinned")
        return 1
    
    sleep_time = 1.0 / args.update_hz
    
    try:
        loop_count = 0
        while True:
            loop_count += 1
            print(f"Starting round {loop_count}...")
            
            start_time = time.time()
            
            for x, y in circular_path(args.center_x, args.center_y, args.radius, 
                                     args.duration, args.update_hz):
                update_camera_modes(camera_map, robot_coords_map, x, y)
                print(f"  Position: ({x:4d}, {y:4d})", end='\r')
                
                time.sleep(sleep_time)
            
            elapsed = time.time() - start_time
            print(f"\nRound {loop_count} complete in {elapsed:.1f} seconds")
            
            # Check if we should stop
            if args.loops > 0 and loop_count >= args.loops:
                break
    
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    finally:
        camera_map.close()
        robot_coords_map.close()
        print(f"Total rounds completed: {loop_count}")
        return 0

if __name__ == '__main__':
    exit(main())
