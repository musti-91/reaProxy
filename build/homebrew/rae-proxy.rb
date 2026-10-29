cask "rae-proxy" do
  version "__VERSION__"
  sha256 "__SHA256__"

  url "https://github.com/musti-91/reaProxy/releases/download/#{version}/RaeProxy-#{version}-arm64.dmg"
  name "Rae Proxy"
  desc "HTTP/HTTPS debugging proxy"
  homepage "https://github.com/musti-91/reaProxy"

  depends_on arch: :arm64
  depends_on macos: ">= :ventura"

  app "Rae Proxy.app"

  zap trash: [
    "~/Library/Application Support/Rae Proxy",
    "~/Library/Preferences/app.rae.proxy.plist",
  ]
end
