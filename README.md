# go-libp2p-tls

[![](https://img.shields.io/badge/made%20by-Protocol%20Labs-blue.svg?style=flat-square)](https://protocol.ai)
[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](http://libp2p.io/)
[![](https://img.shields.io/badge/freenode-%23libp2p-yellow.svg?style=flat-square)](http://webchat.freenode.net/?channels=%23libp2p)
[![GoDoc](https://godoc.org/github.com/libp2p/go-libp2p-tls?status.svg)](https://godoc.org/github.com/libp2p/go-libp2p-tls)
[![Linux Build Status](https://img.shields.io/travis/libp2p/go-libp2p-tls/master.svg?style=flat-square&label=linux+build)](https://travis-ci.org/libp2p/go-libp2p-tls)
[![Code Coverage](https://img.shields.io/codecov/c/github/libp2p/go-libp2p-tls/master.svg?style=flat-square)](https://codecov.io/gh/libp2p/go-libp2p-tls/)
[![Discourse posts](https://img.shields.io/discourse/https/discuss.libp2p.io/posts.svg)](https://discuss.libp2p.io)

> go-libp2p's TLS encrypted transport

Package `go-libp2p-tls` is a libp2p [conn security transport](https://github.com/libp2p/go-conn-security). It uses TLS to setup the communication channel.

## Install

`go-libp2p-tls` is a standard Go module which can be installed with:

```sh
go get github.com/libp2p/go-libp2p-tls
```

Note that `go-libp2p-tls` is packaged with Gx, so it is recommended to use Gx to install and use it (see the Usage section).

## Usage

This module is packaged with [Gx](https://github.com/whyrusleeping/gx). In order to use it in your own project it is recommended that you:

```sh
go get -u github.com/whyrusleeping/gx
go get -u github.com/whyrusleeping/gx-go
cd <your-project-repository>
gx init
gx import github.com/libp2p/go-libp2p-tls
gx install --global
gx-go --rewrite
```

Please check [Gx](https://github.com/whyrusleeping/gx) and [Gx-go](https://github.com/whyrusleeping/gx-go) documentation for more information.

## Contribute

Feel free to join in. All welcome. Open an [issue](https://github.com/libp2p/go-libp2p-tls/issues)!

This repository falls under the IPFS [Code of Conduct](https://github.com/libp2p/community/blob/master/code-of-conduct.md).

### Want to hack on IPFS?

[![](https://cdn.rawgit.com/jbenet/contribute-ipfs-gif/master/img/contribute.gif)](https://github.com/ipfs/community/blob/master/CONTRIBUTING.md)

## License

MIT
