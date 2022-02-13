# Totsugekitai DeBugger

自作デバッガ

## TODO

- [x] ブレークポイントをセット
- [x] ブレークポイントから復帰
- [x] レジスタをダンプ
- [x] メモリをダンプ
- [x] シンボル一覧を表示
- [ ] レジスタ書き換え
- [ ] ウォッチポイント
    - [ ] メモリ
    - [ ] 変数
- [ ] スタックフレーム
    - [ ] backtrace
    - [ ] local variables
    - [ ] args
- [ ] 変数のセット

## memo

### デバッガの実装

- [ptrace入門](https://www.amazon.co.jp/ptrace%E5%85%A5%E9%96%80-ptrace%E3%81%AE%E4%BD%BF%E3%81%84%E6%96%B9-%E5%A4%A7%E5%B1%B1%E6%81%B5%E5%BC%98-ebook/dp/B07X2PCH7K)
- [デバッガ自作から学ぶ低レイヤー](https://naotechnology.hatenablog.com/entry/2019/12/21/083423)
- [デバッガ自作から学ぶ低レイヤ２](https://naotechnology.hatenablog.com/entry/2019/12/31/124727)

### その他

- [Rustとgithub actionsでCI環境構築](https://zenn.dev/naokifujita/articles/c890954165c21f)
- [Rust のデバッグチートシート](https://qiita.com/legokichi/items/e2f807f70316a916f4be)
