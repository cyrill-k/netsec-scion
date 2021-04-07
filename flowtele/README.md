# Workflow

- Build code on ubuntu 18.04:
  Follow [SCION build instruction](https://scion.docs.anapaya.net/en/latest/build/setup.html)

  `./scion.sh bazel_remote`

  `bazel build //...`

- Create one or several QUIC listeners on the *client* side:
  `go run listener/quic_listener.go`

- Create a fshaper (traffic shaper) on the *server* side:
  `go run socket.go --fshaper-only`

- Create one or several QUIC senders on the *server* side:
  `go run socket.go --quic-sender-only`

Enable SCION with the `--scion` flag in each of the calls above to use SCION and list all available parameters with `--help`.

# Example

## SCIONLab VMs

- flowtele-ethz 129.132.121.187 (ssh), 129.132.121.187 (ethz)

- flowtele-ohio 3.12.159.15 (ssh), 172.31.2.128 (ethz)

- flowtele-singapore 122.248.221.20 (ssh)

## minimal example (without fshaper)

- On [flowtele-ethz], dump available paths to flowtele-ohio:
  `bazel-bin/go/flowtele/flowtele_socket_/flowtele_socket -remote-ia 16-ffaa:0:1004 -mode fetch >paths.txt`

- On [flowtele-ohio], start two listeners:
  `bazel-bin/go/flowtele/listener/flowtele_listener_/flowtele_listener -scion -local-ia 16-ffaa:0:1004 -ip 172.31.2.128 -port 40000`

- On [flowtele-ethz], start two connections to flowtele-ohio with the first path in paths.txt:
  `bazel-bin/go/flowtele/flowtele_socket_/flowtele_socket -scion -quic-sender-only -local-ia 17-ffaa:0:1102 -local-ip 129.132.121.187 -local-port 40000 -remote-ia 16-ffaa:0:1004 -ip 172.31.2.128 -port 40000 -paths-file paths.txt -paths-index 0`
