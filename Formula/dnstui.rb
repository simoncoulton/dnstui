class Dnstui < Formula
  desc "DNS, e-mail authentication, blocklist, WHOIS and TLS checks in the terminal"
  homepage "https://github.com/simoncoulton/dnstui"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/simoncoulton/dnstui/releases/download/v0.1.0/dnstui-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "7ed18577870d43aeec0d6e2f5ef83a54759a145d3d7f7e7c6724e1b3fbd42081"
    end
    on_intel do
      url "https://github.com/simoncoulton/dnstui/releases/download/v0.1.0/dnstui-v0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "5b2b03c718a40a0a4bacfec5c65303a054e6d70190d2ce79d893497b2efc5961"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/simoncoulton/dnstui/releases/download/v0.1.0/dnstui-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5feb1c42d5ceb44b36388999eb6efe26b62c041c6333a40f01e4ebc188ad7939"
    end
    on_intel do
      url "https://github.com/simoncoulton/dnstui/releases/download/v0.1.0/dnstui-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bcce89b036a53f38c36611ea4f9b0d90d6d53bba923c3aa04e9f38636a115c6f"
    end
  end

  def install
    bin.install "dnstui"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/dnstui --version")
  end
end
