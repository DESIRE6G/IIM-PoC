# P4-eBPF video filtering

Using P4 and eBPF-PSA to reduce video traffic.

## How to set it up?

Dependencies: vlc, ffmpeg, wget, jq, tcpdump, python3.x-venv, git

1. Build a docker container with the P4 compiler supporting the eBPF-PSA backend. (This will take a while.)

    ```
    make p4c-docker-setup
    ```

2. Build nikks to be able to load and unload the eBPF code.

    ```
    make nikss-setup
    ```

## A short guided tour

Directory structure:

- **p4src**: the P4 source code.
- **p4c-docker**: a dockerised P4 compiler with the right configuration. 
- **p4c-docker/p4c-home**: a shared folder between the host and the Docker container. Its content is automatically managed and does not require version control.
- **sample-videos**: sample video files for testing.
- **out**: the destination of build artifacts.
- **nikss**: a git submodule used to load/unload and configure the eBPF code.
- **scripts**: convenience scripts to run tests and measurements.

Important commands:

- ```make build``` : build the P4 code
- To play locally using network namespaces:
    - ```netns-testbed-up```
    - ```netns-testbed-ping```
    - ```netns-testbed-down```

