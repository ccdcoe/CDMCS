# Build

See
* https://raw.githubusercontent.com/aol/moloch/master/easybutton-build.sh

While dep/rpm install is preferred these days, sometimes a custom build can save the day. A stable build may have unfixed bugs or might be missing critical functionality (missing parsers, etc). Furthermore, understanding how something is built will help you debug it in the future, regardless of how you deploy it in production.

## General build concepts

Moloch follows a standard *configure, make, make install*...in principle. It is actually comprised of multiple modules written in C and NodeJS (with additional scripting in Perl). Packaged `easybutton-build.sh` script essentially covers *configure* and *make* steps of this process, while *make install* does exactly that for components written in C and also builds NodeJS modules via *npm install*.

Note that Moloch attempts to bundle most dependencies as static libraries enclosed in project and deployment directories. That includes NodeJS and Npm (Node package manager), which must be present and and executable in *PATH* in order to deoploy the parts written in node. This can lead to a lot of confusion for those uninitiated to software deployment. One of the cleaner ways of dealing with this problem is to simply add Moloch binaries folder to the *PATH* environment variable.

```
export PATH=$PATH:/data/moloch/bin
```

Please adjust `/data/moloch` prefix accordingly. **It is up to you where Moloch is built and deployed**. Environment variables must also be explicitly present in all scripts and terminals that wish to invoke any binaries in PATH. Adding this line to `$HOME/.profile` or `$HOME/.bashrc` (or `.zshrc` if you are a hipster) will ensure that these binaries are always present for logged in terminal users, but not for headless init/systemd services.
