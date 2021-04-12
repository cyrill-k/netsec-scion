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

## minimal example (with fshaper)

- Make sure that both the flowtele binaries and the athena scripts are pushed to the servers (can use `scripts/push-scion-repo` to synchronize)

- On [flowtele-ethz], dump available paths to flowtele-ohio:
  `bazel-bin/go/flowtele/flowtele_socket_/flowtele_socket -remote-ia 16-ffaa:0:1004 -mode fetch >paths.txt`

- On [flowtele-ethz], start the athena script which calculates the congestion control parameter updates from the rates reported by the QUIC senders:
  `python3.6 athena_m2.py 2`

- On [flowtele-ethz], start the fshaper:
  `bazel-bin/go/flowtele/flowtele_socket_/flowtele_socket --fshaper-only --scion`

- (Optionally) on [flowtele-ethz], verify that the fshaper was started correctly:
  `busctl --user list` should show `ch.ethz.netsec.flowtele.scionsocket`
  `busctl --user introspect ch.ethz.netsec.flowtele.scionsocket /ch/ethz/netsec/flowtele/scionsocket` should show the different signals sent by the QUIC senders (`reportCwnd`, `reportLost`, and `reportRtt`) and the function called by the athena script (`ApplyControl`).

- On [flowtele-ohio], start three listeners:
  `bazel-bin/go/flowtele/listener/flowtele_listener_/flowtele_listener -ip 172.31.2.128 -port-range 3 -scion -local-ia 16-ffaa:0:1004 -num 1`

- On [flowtele-ethz], start three connections to flowtele-ohio with the first path in paths.txt:
  `bazel-bin/go/flowtele/flowtele_socket_/flowtele_socket -remote-ia 16-ffaa:0:1004 -ip 172.31.2.128 -port-range -quic-sender-only -paths-file paths.txt -paths-index 0 -scion -local-ip 129.132.121.187 -local-port 40000 -local-ia 17-ffaa:0:1102 -num 3`
