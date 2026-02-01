# Homebrew formula for hush CLI
# Install: brew install hushclaw/tap/hush
# Or from local: brew install --build-from-source ./HomebrewFormula/hush.rb
#
# SHA256 is automatically updated by the release workflow.
# To calculate SHA256 manually:
#   curl -sL https://github.com/hushclaw/hushclaw/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

class Hush < Formula
  desc "CLI for hushclaw security verification and policy enforcement"
  homepage "https://github.com/hushclaw/hushclaw"
  url "https://github.com/hushclaw/hushclaw/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_WILL_BE_UPDATED_ON_RELEASE"
  license "MIT"
  head "https://github.com/hushclaw/hushclaw.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/hush-cli")

    # Generate shell completions
    generate_completions_from_executable(bin/"hush", "completions")

    # Install hushd daemon binary
    system "cargo", "install", *std_cargo_args(path: "crates/hushd")

    # Install service files and documentation
    (share/"hushd").install "deploy/config.yaml" => "config.yaml.example"
    (share/"hushd").install "deploy/README.md" => "README.md"
    (share/"hushd/systemd").install Dir["deploy/systemd/*"]
    (share/"hushd/launchd").install Dir["deploy/launchd/*"]

    # Create default directories
    (var/"lib/hushd").mkpath
    (var/"log/hushd").mkpath
    (etc/"hushd").mkpath
  end

  def post_install
    # Install example config if none exists
    unless (etc/"hushd/config.yaml").exist?
      (etc/"hushd/config.yaml").write (share/"hushd/config.yaml.example").read
    end
  end

  def caveats
    <<~EOS
      To start hushd as a background service:

        # User-level (runs as current user)
        brew services start hush

        # System-level (runs as root, requires sudo)
        sudo brew services start hush

      Configuration file:
        #{etc}/hushd/config.yaml

      Log files:
        #{var}/log/hushd/

      Data directory:
        #{var}/lib/hushd/

      Service files are installed to:
        #{share}/hushd/

      For manual installation on Linux:
        cp #{share}/hushd/systemd/hushd.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now hushd

      For more information, see:
        #{share}/hushd/systemd/README.md
        #{share}/hushd/launchd/README.md
    EOS
  end

  service do
    run [opt_bin/"hushd", "--config", etc/"hushd/config.yaml"]
    keep_alive true
    log_path var/"log/hushd/hushd.log"
    error_log_path var/"log/hushd/hushd.error.log"
    working_dir var/"lib/hushd"
    environment_variables RUST_LOG: "info"
  end

  test do
    assert_match "hush #{version}", shell_output("#{bin}/hush --version")

    # Test basic help
    assert_match "security verification", shell_output("#{bin}/hush --help")

    # Test hushd version
    assert_match "hushd #{version}", shell_output("#{bin}/hushd --version")

    # Test hushd show-config
    assert_match "ruleset:", shell_output("#{bin}/hushd show-config 2>&1")
  end
end
