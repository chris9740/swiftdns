# Contributing to Swiftdns

Thank you for considering contributing to Swiftdns.

## Style Guides

### Commit messages

Commit messages should follow the [Semantic Commit Messages](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716) convention. Make sure they never exceed 72 in length.

### Verify conformity before commit

This repository has a `prepare-commit-msg` hook that ensures the code is formatted by clippy, passes the tests, as well as making sure the commit message follows the conventions above.

Using this hook is recommended in order to make your developing experience as frictionless as possible, but it is not required.

You can adopt our hook by running the following command:

```bash
git config core.hooksPath .github/hooks/
```

Once you've ran the command above, the hook will be executed every time you run `git commit`, and will cancel the commit if the commit message is improper or if the code doesn't pass the tests.

## Tips

You can use the `dig` command to send a DNS query to the Swiftdns listener: `dig @127.0.0.1 -p 5053 example.com`
