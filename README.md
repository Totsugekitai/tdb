# TDB

(Toy|Tiny|Totsugekitai) DeBugger written in Rust

## TODO

- [x] step instruction
- [x] breakpoint
    - [x] set
    - [x] restore
- [x] dump registers
- [x] dump memory
- [x] list symbols
- [ ] write
    - [ ] memory
    - [ ] register
    - [ ] local/global variable
- [ ] watchpoint
    - [x] memory
    - [x] register
    - [ ] variable
- [ ] dump stackframe
    - [x] backtrace
    - [ ] local variables
    - [ ] args

## memo

### debugger implementation

- [ptrace入門](https://www.amazon.co.jp/ptrace%E5%85%A5%E9%96%80-ptrace%E3%81%AE%E4%BD%BF%E3%81%84%E6%96%B9-%E5%A4%A7%E5%B1%B1%E6%81%B5%E5%BC%98-ebook/dp/B07X2PCH7K)
    - ptraceの使用方法、ブレークポイントの構築・復帰
- [デバッガ自作から学ぶ低レイヤー](https://naotechnology.hatenablog.com/entry/2019/12/21/083423)
- [デバッガ自作から学ぶ低レイヤ２](https://naotechnology.hatenablog.com/entry/2019/12/31/124727)
    - 全体的な知識
- [Binary Hacks](https://www.oreilly.co.jp/books/4873112885/)
    - 5章Hack63: Cでバックトレースを表示する

### misc

- [Rustとgithub actionsでCI環境構築](https://zenn.dev/naokifujita/articles/c890954165c21f)
- [Rust のデバッグチートシート](https://qiita.com/legokichi/items/e2f807f70316a916f4be)
