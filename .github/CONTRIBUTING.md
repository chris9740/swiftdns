# Contributing to Swiftdns

Thank you for considering contributing to Swiftdns.

## Style Guides

### Commit messages

Commit messages should adhere to the [Semantic Commit Messages](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716) convention. Ensure each line of the commit message does not exceed 72 characters.

### Installing hooks

This repository uses a `prepare-commit-msg` hook to format code with Clippy, run tests, and verify that the commit message follows our conventions. This helps maintain code quality and consistency.

Using this hook is recommended in order to make your developing experience as frictionless as possible, but it is not required.

You can adopt our hook by running the following command:

```bash
git config core.hooksPath .github/hooks/
```

Once you've ran the command above, the hook will be executed every time you run `git commit`, and will cancel the commit if the commit message is improper or if the code doesn't pass the tests.

**Note**: To debug the hook, you can execute it directly to test its functionality without committing: `.github/hooks/prepare-commit-msg "fix: implement fix for ..."`. The hook will perform all checks as if it were triggered by a commit attempt.

## Tips

You can use the `dig` command to send a DNS query to the Swiftdns listener: `dig @127.0.0.1 -p 5053 example.com`
