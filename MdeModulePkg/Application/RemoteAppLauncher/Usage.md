# Usage

## --help / -h / -? / --usage

Print usage and exit.

## --list

List id and name of files on the remote server.

## --load [id]

Load a file from the remote server and execute.

`id` specifies id of the file we would like to receive.

## --ip [str]

Specify remote IP.

`str` should be an IPv4 address. **Required for listing apps and loading app**.

Example:

```bash
./RemoteAppLauncher.efi --ip 10.80.42.221
```

## --port [port]

Specify remote port. **Required for listing apps and loading app**.

Example:

```bash
./RemoteAppLauncher.efi --port 65472
```
