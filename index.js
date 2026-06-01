const express = require("express");
const forge = require("node-forge");
const axios = require("axios");
const app = express();
app.use(express.json());

const CUIT     = process.env.CUIT || "27303744172";
const CERT_B64 = process.env.CERT_B64 || "";
const KEY_B64  = process.env.KEY_B64  || "";
const WSAA_URL = "https://wsaa.afip.gov.ar/ws/services/LoginCms";
const WSFE_URL = "https://servicios1.afip.gov.ar/wsfev1/service.asmx";

let cachedToken = null;
let cachedSign  = null;
let tokenExpira = null;

function getCertAndKey() {
  // Los valores son DER en base64 — los convertimos a PEM
  const certDer = Buffer.from(CERT_B64, "base64");
  const keyDer  = Buffer.from(KEY_B64,  "base64");

  const certAsn1 = forge.asn1.fromDer(forge.util.createBuffer(certDer));
  const cert     = forge.pki.certificateFromAsn1(certAsn1);

  const keyAsn1  = forge.asn1.fromDer(forge.util.createBuffer(keyDer));
  const privKey  = forge.pki.privateKeyFromAsn1(keyAsn1);

  return { cert, privKey };
}

function firmarTRA(traXml) {
  const { cert, privKey } = getCertAndKey();

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(traXml, "utf8");
  p7.addCertificate(cert);
  p7.addSigner({
    key: privKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() }
    ]
  });
  p7.sign();

  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, "binary").toString("base64");
}

function formatFecha(d) {
  return d.toISOString().replace(/\.\d{3}Z$/, "-00:00");
}
async function obtenerToken() {
  const ahora = new Date();
  if (cachedToken && tokenExpira && ahora < tokenExpira) {
    return { token: cachedToken, sign: cachedSign };
  }

  const expira   = new Date(ahora.getTime() + 10 * 60 * 1000);
  const uniqueId = Math.floor(Math.random() * 1000000);

  const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${uniqueId}</uniqueId>
    <generationTime>${formatFecha(ahora)}</generationTime>
    <expirationTime>${formatFecha(expira)}</expirationTime>
  </header>
  <service>wsfe</service>
</loginTicketRequest>`;

  const firma = firmarTRA(tra);

  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov.ar">
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${firma}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

  const resp = await axios.post(WSAA_URL, soap, {
    headers: { "Content-Type": "text/xml; charset=utf-8", "SOAPAction": "" },
    validateStatus: () => true
  });

  console.log("Status WSAA:", resp.status);
  const xml = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
  console.log("Respuesta WSAA:", xml.substring(0, 400));

const unescaped = xml.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"');
const token = unescaped.match(/<token>([^<]+)<\/token>/)?.[1];
const sign  = unescaped.match(/<sign>([^<]+)<\/sign>/)?.[1];

  if (!token) throw new Error("No se pudo obtener token. Respuesta: " + xml.substring(0, 500));

  cachedToken = token;
  cachedSign  = sign;
  tokenExpira = new Date(ahora.getTime() + 9 * 60 * 1000);

  return { token, sign };
}

app.get("/ultimo-numero", async (req, res) => {
  try {
    const { token, sign } = await obtenerToken();
    const ptoVta   = req.query.ptoVta   || 3;
    const cbteTipo = req.query.cbteTipo || 11;

    const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${CUIT}</ar:Cuit>
      </ar:Auth>
      <ar:PtoVta>${ptoVta}</ar:PtoVta>
      <ar:CbteTipo>${cbteTipo}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soapenv:Body>
</soapenv:Envelope>`;

    const resp = await axios.post(WSFE_URL, soap, {
      headers: {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado"
      }
    });

    const nro = resp.data.match(/<CbteNro>([^<]+)<\/CbteNro>/)?.[1] || "0";
    res.json({ ok: true, ultimoNumero: parseInt(nro) });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/emitir", async (req, res) => {
  try {
    const { token, sign } = await obtenerToken();
    const { ptoVta, nroComprobante, fecha, docTipo, docNro, total } = req.body;
    const fechaStr = fecha.replace(/-/g, "");

    const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soapenv:Body>
    <ar:FECAESolicitar>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${CUIT}</ar:Cuit>
      </ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq>
          <ar:CantReg>1</ar:CantReg>
          <ar:PtoVta>${ptoVta}</ar:PtoVta>
          <ar:CbteTipo>11</ar:CbteTipo>
        </ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>1</ar:Concepto>
            <ar:DocTipo>${docTipo}</ar:DocTipo>
            <ar:DocNro>${docNro}</ar:DocNro>
            <ar:CbteDesde>${nroComprobante}</ar:CbteDesde>
            <ar:CbteHasta>${nroComprobante}</ar:CbteHasta>
            <ar:CbteFch>${fechaStr}</ar:CbteFch>
            <ar:ImpTotal>${parseFloat(total).toFixed(2)}</ar:ImpTotal>
            <ar:ImpTotConc>0.00</ar:ImpTotConc>
            <ar:ImpNeto>${parseFloat(total).toFixed(2)}</ar:ImpNeto>
            <ar:ImpOpEx>0.00</ar:ImpOpEx>
            <ar:ImpIVA>0.00</ar:ImpIVA>
            <ar:ImpTrib>0.00</ar:ImpTrib>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soapenv:Body>
</soapenv:Envelope>`;

    const resp = await axios.post(WSFE_URL, soap, {
      headers: {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "http://ar.gov.afip.dif.FEV1/FECAESolicitar"
      }
    });

    const xml       = resp.data;
    const resultado = xml.match(/<Resultado>([^<]+)<\/Resultado>/)?.[1];
    if (resultado !== "A") {
      const msg = xml.match(/<Msg>([^<]+)<\/Msg>/)?.[1] || "Error desconocido de ARCA";
      throw new Error(msg);
    }

    const cae    = xml.match(/<CAE>([^<]+)<\/CAE>/)?.[1];
    const vtoCae = xml.match(/<CAEFchVto>([^<]+)<\/CAEFchVto>/)?.[1];
    res.json({ ok: true, cae, vtoCae });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/", (req, res) => res.json({ status: "Facturador ARCA activo ✅" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Servidor corriendo en puerto " + PORT));
