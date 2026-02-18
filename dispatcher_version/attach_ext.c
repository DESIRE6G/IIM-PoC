#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ext_obj> <target_prog_id> <target_func> <pin_path>\n", argv[0]);
        return 1;
    }

    const char *obj_file = argv[1];
    int target_prog_id = atoi(argv[2]);
    const char *target_func = argv[3];
    const char *pin_path = argv[4];

    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, err;

    // Open BPF object
    obj = bpf_object__open(obj_file);
    if (!obj) {
        fprintf(stderr, "Failed to open %s: %s\n", obj_file, strerror(errno));
        return 1;
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char map_pin_path[256];
        snprintf(map_pin_path, sizeof(map_pin_path), "/sys/fs/bpf/xdp_pipeline/%s", map_name);
        
        // Try to reuse the pinned map from dispatcher
        int fd = bpf_obj_get(map_pin_path);
        if (fd >= 0) {
            bpf_map__reuse_fd(map, fd);
        }
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "No program found in %s\n", obj_file);
        bpf_object__close(obj);
        return 1;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_EXT);

    int target_fd = bpf_prog_get_fd_by_id(target_prog_id);
    if (target_fd < 0) {
        fprintf(stderr, "Failed to get fd for prog %d: %s\n", target_prog_id, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_program__set_attach_target(prog, target_fd, target_func);
    if (err) {
        fprintf(stderr, "Failed to set attach target: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_obj_pin(prog_fd, pin_path);
    if (err) {
        fprintf(stderr, "Failed to pin program to %s: %s\n", pin_path, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char map_pin_path[256];
        snprintf(map_pin_path, sizeof(map_pin_path), "/sys/fs/bpf/xdp_pipeline/%s", map_name);
        
        int existing_fd = bpf_obj_get(map_pin_path);
        if (existing_fd >= 0) {
            close(existing_fd);
            continue;  // Map already exists, skip pinning
        }
        
        int map_fd = bpf_map__fd(map);
        if (map_fd >= 0) {
            err = bpf_obj_pin(map_fd, map_pin_path);
            if (err && errno != EEXIST) {
                fprintf(stderr, "Warning: Failed to pin map %s: %s\n", map_name, strerror(errno));
            }
        }
    }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    char link_pin_path[512];
    snprintf(link_pin_path, sizeof(link_pin_path), "%s_link", pin_path);
    
    err = bpf_link__pin(link, link_pin_path);
    if (err) {
        fprintf(stderr, "Failed to pin link to %s: %s\n", link_pin_path, strerror(-err));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("Successfully attached and pinned to %s (link: %s)\n", pin_path, link_pin_path);
    
    return 0;
}
