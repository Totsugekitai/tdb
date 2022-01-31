use clap::Parser;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// target file
    #[clap(short, long)]
    pub file: String,

    /// arguments passing target file
    #[clap(short, long)]
    pub args: Vec<String>,
}
