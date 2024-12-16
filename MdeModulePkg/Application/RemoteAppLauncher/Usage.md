# Usage

## Cli Options

### --help / -h / -? / --usage

Print usage and exit.

### --list

List id and name of files on the remote server.

### --load [id]

Load a file from the remote server and execute.

`id` specifies id of the file we would like to receive.

### --ip [str]

Specify remote IP.

`str` should be an IPv4 address. **Required for listing apps and loading app**.

Example:

```bash
./RemoteAppLauncher.efi --ip 10.80.42.221
```

### --port [port]

Specify remote port. **Required for listing apps and loading app**.

Example:

```bash
./RemoteAppLauncher.efi --port 65472
```

### --save-binary-to [file]

Specify path to save binary downloaded from remote server.

You can ignore this option. If you do, binary would be saved to somewhere that doesn't important and `--remove-binary-after-execution` flag would be set.

Example:

```bash
./RemoteAppLauncher.efi --save-binary-to ./Hello.efi
```

### --remove-binary-after-execution

Remove binary downloaded from remote after execution.

This flag is automatically set if you didn't set `--save-binary-to`.

Example:

```bash
./RemoteAppLauncher.efi --remove-binary-after-execution
```

### --cli [str]

Command-line arguments to be passed to sub-process.

Example:

```bash
./RemoteAppLauncher.efi --cli "-Wall -o app app.c"
```

## Examples

### Query apps available on remote

```bash
./RemoteAppLauncher.efi --ip 10.80.42.221 --port 65472 --list
```

### Load app, save and run

```bash
./RemoteAppLauncher.efi --ip 10.80.42.221 --port 65472 --load 33 --save-binary-to Hello.efi
```
