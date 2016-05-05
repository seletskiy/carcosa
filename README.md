#### *You're in the Carcosa now&hellip;* <img width="207px" align="left" src="https://cloud.githubusercontent.com/assets/674812/14978039/e1cd0130-113a-11e6-991a-729c40af89ec.png"/>

## What is it?

*carcosa* is a tool for securely storing secrets like password in the
public/private git repositories.

*carcosa* stores secrets (like passwords) under the tokens (e.g. names).

Tokens and secrets are encrypted via AES and it's impossible to decrypt one
without another. No one can get the list of tokens without the knowledge of the
*master password*.

## How to use carcosa?

### Using existing repo

You can use *carcosa* to store secrets in any repository. You can use `-S` to
sync local repo with remote:

```
carcosa -S
```

### Using new repo

First, you need to initialize repository via `git init`.

Then you can set repo remote via `git remote add` or specify remote every
time via `-r` flag.

```
git init
carcosa -Sr git://path.to/remote.git
```

### Adding secrets

Secrets can be added by using `-A` flag:

```
carcosa -A my-super-password
```

Note that a new added secret will be synced to the remote (if any)
automatically. If you want to add a new secret locally only, use `-n` flag:

```
carcosa -An my-super-password
```

Then you can sync it remote any time using `-S` flag:

```
carcosa -S
```

### Listing secrets

```
carcosa -L
```

Will list all tokens after entering master password.

Note that this operation will not sync secrets before listing. If you
want to sync it before, use `-y` flag:

```
carcosa -Ly
```

### Getting secret by token

```
carcosa -G my-super-password
```

It will output contents of the secret, decrypted by master password.

Note that it will not sync with the remote repo first. If you want to, you
can specify flag `-y

## Advanced usage

### Caching master password

Add `-c` flag to every command for storing master key (encrypted too) in the
read-by-you only cache file. Then, everytime you invoke carcosa with `-c` flag
master key will be read from that file and will not be asked again.

```
carcosa -Lc  # enter master key once
carcosa -L   # use carcosa without entering master key
```

### Using UI

Sample dmenu-based UI available at: https://github.com/deadcrew/deadfiles/blob/master/bin/carcosa-ui

By default, it will look into `~/.secrets` directory and expect to find secrets
repo there. Alternatively, `$SECRETS_REPOSITORY` can be specified as
environment variable to override that location.

Before usage, master key should be cached by invoking any retrieve or store
command with `-c` flag. Like:

```
carcosa -Lc
```
