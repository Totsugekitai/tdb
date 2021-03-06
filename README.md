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
    - [x] memory
    - [x] register
    - [ ] local/global variable
- [ ] watchpoint
    - [x] memory
    - [x] register
    - [ ] variable
- [ ] dump stackframe
    - [x] backtrace
    - [ ] local variables
    - [ ] args
- [ ] relocation symbol resolution

## memo

### debugger implementation

- [ptrace入門(ja)](https://www.amazon.co.jp/ptrace%E5%85%A5%E9%96%80-ptrace%E3%81%AE%E4%BD%BF%E3%81%84%E6%96%B9-%E5%A4%A7%E5%B1%B1%E6%81%B5%E5%BC%98-ebook/dp/B07X2PCH7K)
    - usage of ptrace, construct or restore breakpoint
- [デバッガ自作から学ぶ低レイヤー(ja)](https://naotechnology.hatenablog.com/entry/2019/12/21/083423)
- [デバッガ自作から学ぶ低レイヤ２(ja)](https://naotechnology.hatenablog.com/entry/2019/12/31/124727)
    - debugger implementation info
- [Binary Hacks(ja)](https://www.oreilly.co.jp/books/4873112885/)
    - Section 5 Hack63: print backtrace in C
- [Writing a Linux Debugger(en)](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)
- [A debugger from scratch(en)](https://medium.com/@lizrice/a-debugger-from-scratch-part-1-7f55417bc85f)

### misc

- [Rustとgithub actionsでCI環境構築(ja)](https://zenn.dev/naokifujita/articles/c890954165c21f)
- [Rust のデバッグチートシート(ja)](https://qiita.com/legokichi/items/e2f807f70316a916f4be)
