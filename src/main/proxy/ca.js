// Root certificate authority + on-the-fly leaf certificates for HTTPS interception.
const fs = require("fs");
const path = require("path");
const os = require("os");
const tls = require("tls");
const net = require("net");
const crypto = require("crypto");
const forge = require("node-forge");

const pki = forge.pki;

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  return {
    privateKeyPem: privateKey,
    publicKey: pki.publicKeyFromPem(publicKey),
    privateKey: pki.privateKeyFromPem(privateKey),
  };
}

function serial() {
  return "01" + crypto.randomBytes(15).toString("hex");
}

class CertAuthority {
  constructor(dir) {
    this.dir = dir;
    this.certPath = path.join(dir, "rae-proxy-ca.pem");
    this.keyPath = path.join(dir, "rae-proxy-ca.key");
    this.contexts = new Map();
    this.load();
    this.leaf = keyPair();
  }

  load() {
    if (fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)) {
      this.caCertPem = fs.readFileSync(this.certPath, "utf8");
      this.caCert = pki.certificateFromPem(this.caCertPem);
      this.caKey = pki.privateKeyFromPem(fs.readFileSync(this.keyPath, "utf8"));
    } else {
      this.generate();
    }
  }

  generate() {
    const kp = keyPair();
    const cert = pki.createCertificate();
    cert.publicKey = kp.publicKey;
    cert.serialNumber = serial();
    cert.validity.notBefore = new Date(Date.now() - 86400e3);
    cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400e3);
    const stamp = new Date().toISOString().slice(0, 10);
    const attrs = [
      {
        name: "commonName",
        value: `Rae Proxy CA (${os.hostname().split(".")[0]}, ${stamp})`,
      },
      { name: "organizationName", value: "Rae Proxy" },
      { shortName: "OU", value: "Rae Proxy Local Debugging" },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: "basicConstraints", cA: true, critical: true },
      {
        name: "keyUsage",
        keyCertSign: true,
        cRLSign: true,
        digitalSignature: true,
        critical: true,
      },
      { name: "subjectKeyIdentifier" },
    ]);
    cert.sign(kp.privateKey, forge.md.sha256.create());
    this.caCert = cert;
    this.caKey = kp.privateKey;
    this.caCertPem = pki.certificateToPem(cert);
    fs.mkdirSync(this.dir, { recursive: true });
    fs.writeFileSync(this.certPath, this.caCertPem);
    fs.writeFileSync(this.keyPath, kp.privateKeyPem, { mode: 0o600 });
    this.contexts.clear();
  }

  regenerate() {
    this.generate();
  }

  get commonName() {
    return this.caCert.subject.getField("CN").value;
  }

  leafCertPem(host) {
    const cert = pki.createCertificate();
    cert.publicKey = this.leaf.publicKey;
    cert.serialNumber = serial();
    cert.validity.notBefore = new Date(Date.now() - 86400e3);
    cert.validity.notAfter = new Date(Date.now() + 397 * 86400e3);
    cert.setSubject([
      { name: "commonName", value: host.slice(0, 64) },
      { name: "organizationName", value: "Rae Proxy" },
    ]);
    cert.setIssuer(this.caCert.subject.attributes);
    const altNames = net.isIP(host)
      ? [{ type: 7, ip: host }]
      : [{ type: 2, value: host }];
    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      {
        name: "keyUsage",
        digitalSignature: true,
        keyEncipherment: true,
        critical: true,
      },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames },
      { name: "subjectKeyIdentifier" },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: this.caCert.generateSubjectKeyIdentifier().getBytes(),
      },
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());
    return pki.certificateToPem(cert);
  }

  contextFor(host) {
    host = (host || "localhost").toLowerCase();
    let ctx = this.contexts.get(host);
    if (!ctx) {
      ctx = tls.createSecureContext({
        key: this.leaf.privateKeyPem,
        cert: this.leafCertPem(host) + this.caCertPem,
      });
      this.contexts.set(host, ctx);
    }
    return ctx;
  }
}

module.exports = { CertAuthority };
