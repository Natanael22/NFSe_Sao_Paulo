package br.com.nfse.sp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

public class AssinarXML {

	private static String PATHCERTIFICATE = System.getProperty("user.dir") + "/security/certificadoDigital.pfx";
	private static String PASSWDCERTIFICATE = "12345678";

	public static String start(String operacao, String xml) throws Exception {

		String retorno = null;

		switch (operacao) {
		case "PedidoEnvioLoteRPS":
			retorno = assinarEnvio("", xml);
			break;
		case "TesteEnvioLoteRPSRequest":
			retorno = assinarEnvio("", xml);
			break;
		case "PedidoCancelamentoNFe":
			retorno = assinarCancelamento("", xml);
			break;
		case "PedidoConsultaNFe":
			retorno = assinarConsulta("", xml);
			break;
		case "PedidoConsultaLote":
			retorno = assinarConsulta("", xml);
			break;
		default:
			break;

		}
		return retorno;
	}

	/**
	 * LINK - http://www.guj.com.br/t/assinaturas-nfs-e-sao-paulo/135806
	 * 
	 * @param referencia
	 * @param xml
	 * @return XML ASSINADO
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 * @throws SAXException
	 * @throws ParserConfigurationException
	 * @throws NoSuchAlgorithmException
	 */
	private static String assinarEnvio(String referencia, String xml)
			throws KeyStoreException, CertificateException, UnrecoverableEntryException, IOException, SAXException,
			ParserConfigurationException, NoSuchAlgorithmException {

		xml = xml.replace("\n", "").replace("\t", "").replace("\r", "");

		Document doc = documentFactory(xml);

		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(PATHCERTIFICATE), PASSWDCERTIFICATE.toCharArray());
		Enumeration<String> aliasesEnum = ks.aliases();
		String alias = "";

		while (aliasesEnum.hasMoreElements()) {
			alias = (String) aliasesEnum.nextElement();
			if (ks.isKeyEntry(alias)) {
				break;
			}
		}

		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(PASSWDCERTIFICATE.toCharArray()));

		try {

			for (int i = 0; i < doc.getElementsByTagName("RPS").getLength(); i++) {

				String assinatura = criarAssinaturaEnvio(xml, i);

				String hash = assinarTagRPS(assinatura.getBytes());

				NodeList nodes = doc.getElementsByTagName("ChaveRPS");
				Element elemento = doc.createElement("Assinatura");
				Text valor = doc.createTextNode(hash);
				elemento.appendChild(valor);

				nodes.item(i).getParentNode().insertBefore(elemento, nodes.item(i));
			}

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

			Reference ref = fac.newReference(referencia.isEmpty() ? "" : ("#" + referencia),
					fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);

			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

			X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			List x509Content = new ArrayList();
			x509Content.add(cert);
			X509Data xd = kif.newX509Data(x509Content);
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

			DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

			XMLSignature signature = fac.newXMLSignature(si, ki);
			signature.sign(dsc);

			StringWriter fos = new StringWriter();

			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(fos));

			return outputXML(doc);

		} catch (TransformerException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (MarshalException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (XMLSignatureException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidAlgorithmParameterException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;

	}

	private static String assinarConsulta(String referencia, String xml)
			throws KeyStoreException, CertificateException, UnrecoverableEntryException, IOException, SAXException,
			ParserConfigurationException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub

		xml = xml.replace("\n", "").replace("\t", "").replace("\r", "");

		Document doc = documentFactory(xml);

		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(PATHCERTIFICATE), PASSWDCERTIFICATE.toCharArray());
		Enumeration<String> aliasesEnum = ks.aliases();
		String alias = "";

		while (aliasesEnum.hasMoreElements()) {
			alias = (String) aliasesEnum.nextElement();
			if (ks.isKeyEntry(alias)) {
				break;
			}
		}

		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(PASSWDCERTIFICATE.toCharArray()));

		try {

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

			Reference ref = fac.newReference(referencia.isEmpty() ? "" : ("#" + referencia),
					fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);

			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

			X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			List x509Content = new ArrayList();
			x509Content.add(cert);
			X509Data xd = kif.newX509Data(x509Content);
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

			DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

			XMLSignature signature = fac.newXMLSignature(si, ki);
			signature.sign(dsc);

			StringWriter fos = new StringWriter();

			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(fos));

			return outputXML(doc);

		} catch (TransformerException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (MarshalException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (XMLSignatureException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidAlgorithmParameterException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

	private static String assinarCancelamento(String referencia, String xml)
			throws KeyStoreException, CertificateException, UnrecoverableEntryException, IOException, SAXException,
			ParserConfigurationException, NoSuchAlgorithmException {

		xml = xml.replace("\n", "").replace("\t", "").replace("\r", "");

		Document doc = documentFactory(xml);

		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(PATHCERTIFICATE), PASSWDCERTIFICATE.toCharArray());
		Enumeration<String> aliasesEnum = ks.aliases();
		String alias = "";

		while (aliasesEnum.hasMoreElements()) {
			alias = (String) aliasesEnum.nextElement();
			if (ks.isKeyEntry(alias)) {
				break;
			}
		}

		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(PASSWDCERTIFICATE.toCharArray()));

		try {
			
			for(int i=0; i < doc.getElementsByTagName("Detalhe").getLength(); i++) {
			
				String assinatura = criarAssinaturaCancelamento(xml, i);
				String hash = assinarTagRPS(assinatura.getBytes());

				NodeList nodes = doc.getElementsByTagName("ChaveNFe");
				Element elemento = doc.createElement("AssinaturaCancelamento");
				Text valor = doc.createTextNode(hash);
				elemento.appendChild(valor);

				nodes.item(i).getParentNode().insertBefore(elemento, nodes.item(i).getNextSibling());			
			}
			
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

			Reference ref = fac.newReference(referencia.isEmpty() ? "" : ("#" + referencia),
					fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);

			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

			X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
			KeyInfoFactory kif = fac.getKeyInfoFactory();

			List x509Content = new ArrayList();
			x509Content.add(cert);
			X509Data xd = kif.newX509Data(x509Content);
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

			DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

			XMLSignature signature = fac.newXMLSignature(si, ki);
			signature.sign(dsc);

			StringWriter fos = new StringWriter();

			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(fos));

			return outputXML(doc);

		} catch (TransformerException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (MarshalException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (XMLSignatureException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvalidAlgorithmParameterException ex) {
			Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;

	}
  //Metodo para criar a String da tag Assinatura
	private static String criarAssinaturaEnvio(String xml, int index)
			throws SAXException, IOException, ParserConfigurationException {

		StringBuffer assinatura = new StringBuffer();

		Document doc = documentFactory(xml);

		NumberFormat nf = new DecimalFormat("#0.00");

		// Inscrição Municipal do Prestador com 8 posições (dígitos). Completar com
		// zeros à esquerda caso seja necessário.
		String inscricaoPrestador = doc.getElementsByTagName("InscricaoPrestador").item(index).getChildNodes().item(0)
				.getNodeValue();
		if (inscricaoPrestador.length() < 8) {
			for (int i = 0; i < (8 - inscricaoPrestador.length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(inscricaoPrestador);

		// Série do RPS com 5 posições (caracteres). Completar com espaços em branco à
		// direita caso seja necessário.
		String serieRPS = doc.getElementsByTagName("SerieRPS").item(index).getChildNodes().item(0).getNodeValue();
		assinatura.append(serieRPS);
		if (serieRPS.length() < 5) {
			for (int i = 0; i < (5 - serieRPS.length()); i++) {
				assinatura.append(" ");
			}
		}

		// Número do RPS com 12 posições (dígitos). Completar com zeros à esquerda caso
		// seja necessário
		String numeroRPS = doc.getElementsByTagName("NumeroRPS").item(index).getChildNodes().item(0).getNodeValue();

		if (numeroRPS.length() < 12) {
			for (int i = 0; i < (12 - numeroRPS.length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(numeroRPS);

		// Data de emissão do RPS no formato AAAAMMDD (caracteres).
		String dataEmissao = doc.getElementsByTagName("DataEmissao").item(index).getChildNodes().item(0).getNodeValue();
		assinatura.append(dataEmissao.replace("-", ""));

		// Tipo de Tributação do RPS com 1 posição (caractere):
		String tributacaoRPS = doc.getElementsByTagName("TributacaoRPS").item(index).getChildNodes().item(0)
				.getNodeValue();
		assinatura.append(tributacaoRPS);

		// Status do RPS com 1 posição (caractere): N – Normal; C – Cancelado
		String statusRPS = doc.getElementsByTagName("StatusRPS").item(index).getChildNodes().item(0).getNodeValue();
		assinatura.append(statusRPS);

		// Valor ‘S’ (SIM) para ISS Retido (caractere). Valor ‘N’ (NÃO) para Nota Fiscal
		// sem ISS Retido.
		String issRetido = (doc.getElementsByTagName("ISSRetido").item(index).getChildNodes().item(0).getNodeValue()
				.equalsIgnoreCase("false") ? "N" : "T");
		assinatura.append(issRetido);

		// Valor dos Serviços do RPS, incluindo os centavos (sem ponto decimal e sem
		// R$), com 15 posições (dígitos). Exemplo:R$ 500,85 – 000000000050085
		String valorServicos = doc.getElementsByTagName("ValorServicos").item(index).getChildNodes().item(0)
				.getNodeValue();
		String vs = nf.format(Double.valueOf(valorServicos)).replace(",", "");
		if (nf.format(Double.valueOf(valorServicos)).replace(",", "").length() < 15) {
			for (int i = 0; i < (15 - nf.format(Double.valueOf(valorServicos)).replace(",", "").length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(vs);

		// Valor das Deduções do RPS, incluindo os centavos (sem ponto decimal e sem
		// R$), com 15 posições (dígitos). Exemplo:R$ 500,85 – 000000000050085
		String valorDeducoes = doc.getElementsByTagName("ValorDeducoes").item(index).getChildNodes().item(0)
				.getNodeValue();
		String vd = nf.format(Double.valueOf(valorDeducoes)).replace(",", "");
		if (nf.format(Double.valueOf(valorDeducoes)).replace(",", "").length() < 15) {
			for (int i = 0; i < (15 - nf.format(Double.valueOf(valorDeducoes)).replace(",", "").length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(vd);

		// Código do Serviço do RPS com 5 posições (dígitos). Completar com zeros à
		// esquerda caso seja necessário.
		String codigoServico = doc.getElementsByTagName("CodigoServico").item(index).getChildNodes().item(0)
				.getNodeValue();
		if (codigoServico.length() < 5) {
			for (int i = 0; i < (5 - codigoServico.length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(codigoServico);

		// Indicador de CPF/CNPJ com 1 posição (dígito). Valor 1 para CPF. Valor 2 para
		// CNPJ. Valor 3 para Não informado

		if (doc.getElementsByTagName("CPFCNPJTomador").item(index).getNodeName() != null && 
				doc.getElementsByTagName("CPFCNPJTomador").item(index).getChildNodes().item(0).getNodeName().equalsIgnoreCase("CPF")) {
			String cpf = doc.getElementsByTagName("CPFCNPJTomador").item(index).getChildNodes().item(0).getFirstChild().getNodeValue();
			assinatura.append("1");
			if (cpf.length() < 14) {
				for (int i = 0; i < (14 - cpf.length()); i++) {
					assinatura.append("0");
				}
			}
			assinatura.append(cpf);
		} else if (doc.getElementsByTagName("CPFCNPJTomador").item(index).getNodeName() != null
				&& doc.getElementsByTagName("CPFCNPJTomador").item(index).getChildNodes().item(0).getNodeName().equalsIgnoreCase("CNPJ")) {
			String cnpj = doc.getElementsByTagName("CPFCNPJTomador").item(index).getChildNodes().item(0).getFirstChild().getNodeValue();
			assinatura.append("2");
			if (cnpj.length() < 14) {
				for (int i = 0; i < (14 - cnpj.length()); i++) {
					assinatura.append("0");
				}
			}
			assinatura.append(cnpj);
			
		} else {
			assinatura.append("3");
			for (int i = 0; i < 14; i++) {
				assinatura.append("0");
			}
		}
		
		return assinatura.toString();
	}
  //Metodo para criar a String da tag Assinatura
	private static String criarAssinaturaCancelamento(String xml, int index)
			throws SAXException, IOException, ParserConfigurationException {

		StringBuffer assinatura = new StringBuffer();
		Document doc = documentFactory(xml);

		// Inscrição Municipal do Prestador com 8 posições (dígitos). Completar com
		// zeros à esquerda caso seja necessário.
		String inscricaoPrestador = doc.getElementsByTagName("InscricaoPrestador").item(index).getChildNodes().item(0)
				.getNodeValue();

		// Número da NF-e com 12 posições (dígitos). Completar com zeros à esquerda caso
		// seja necessário.
		String numeroNFe = doc.getElementsByTagName("NumeroNFe").item(index).getChildNodes().item(0).getNodeValue();

		if (inscricaoPrestador.length() < 8) {
			for (int i = 0; i < (8 - inscricaoPrestador.length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(inscricaoPrestador);

		if (numeroNFe.length() < 12) {
			for (int i = 0; i < (12 - numeroNFe.length()); i++) {
				assinatura.append("0");
			}
		}
		assinatura.append(numeroNFe);

		return assinatura.toString();
	}

	/**
	 * LINK - http://www.guj.com.br/t/nfe-prefeitura-de-sao-paulo/295921/21
	 * 
	 * @return CHAVE PRIVADA
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 */
	private static PrivateKey getPrivateKey() throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableEntryException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(PATHCERTIFICATE), PASSWDCERTIFICATE.toCharArray());
		String alias = (String) ks.aliases().nextElement();
		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(PASSWDCERTIFICATE.toCharArray()));
		return keyEntry.getPrivateKey();
	}

	/**
	 * LINK - http://www.guj.com.br/t/nfe-prefeitura-de-sao-paulo/295921/21
	 * 
	 * @param textoParaAssinar
	 * @return TEXTO ENCRIPTADO
	 */
	private static String assinarTagRPS(byte[] textoParaAssinar) {
		Signature signer = null;
		String hash = "";
		try {
			signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(getPrivateKey());
			signer.update(textoParaAssinar);
			hash = Base64.getEncoder().encodeToString(signer.sign());
		} catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException ex) {
			return null;
		} catch (KeyStoreException | IOException | CertificateException | UnrecoverableEntryException ex) {
			java.util.logging.Logger.getLogger(AssinarXML.class.getName()).log(Level.SEVERE, null, ex);
		}
		return hash;
	}

	private static Document documentFactory(String xml) throws SAXException, IOException, ParserConfigurationException {

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));

		return document;
	}

	private static String outputXML(Document doc) throws TransformerException {

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();

		trans.transform(new DOMSource(doc), new StreamResult(os));
		String xml = os.toString();

		if ((xml != null) && (!"".equals(xml))) {
			xml = xml.replaceAll("\r\n", "");
			xml = xml.replaceAll(" standalone=\"no\"", "");
		}
		return xml;
	}

	public static void main(String [] args) throws Exception {
    //Teste para Assinar o XML de Cancelamento
		/*System.out.println(AssinarXML.assinarCancelamento("", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" + 
				"<PedidoCancelamentoNFe xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"http://www.prefeitura.sp.gov.br/nfe\">\r\n" + 
				"  <Cabecalho Versao=\"1\" xmlns=\"\">\r\n" + 
				"    <CPFCNPJRemetente>\r\n" + 
				"      <CNPJ>99999997000100</CNPJ>\r\n" + 
				"    </CPFCNPJRemetente>\r\n" + 
				"    <transacao>true</transacao>\r\n" + 
				"  </Cabecalho>\r\n" + 
				"  <Detalhe xmlns=\"\">\r\n" + 
				"    <ChaveNFe>\r\n" + 
				"      <InscricaoPrestador>39616924</InscricaoPrestador>\r\n" + 
				"      <NumeroNFe>17945</NumeroNFe>\r\n" + 
				"    </ChaveNFe>\r\n" + 
				"  </Detalhe>\r\n" +
				"  <Detalhe xmlns=\"\">\r\n" + 
				"    <ChaveNFe>\r\n" + 
				"      <InscricaoPrestador>39616924</InscricaoPrestador>\r\n" + 
				"      <NumeroNFe>17945</NumeroNFe>\r\n" + 
				"    </ChaveNFe>\r\n" + 
				"  </Detalhe>\r\n" +
				"</PedidoCancelamentoNFe>"));*/
    
    //Teste para Assinar o XML de PedidoEnvioLoteRPS somente comm uma RPS
		/*System.out.println(AssinarXML.start("PedidoEnvioLoteRPS", "<PedidoEnvioLoteRPS xmlns=\"http://www.prefeitura.sp.gov.br/nfe\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n" + 
				"	<Cabecalho xmlns=\"\" Versao=\"1\">\r\n" + 
				"		<CPFCNPJRemetente>\r\n" + 
				"			<CNPJ>99999997000100</CNPJ>\r\n" + 
				"		</CPFCNPJRemetente>\r\n" + 
				"		<transacao>false</transacao>\r\n" + 
				"		<dtInicio>2018-02-01</dtInicio>\r\n" + 
				"		<dtFim>2018-02-23</dtFim>\r\n" + 
				"		<QtdRPS>2</QtdRPS>\r\n" + 
				"		<ValorTotalServicos>200</ValorTotalServicos>\r\n" + 
				"		<ValorTotalDeducoes>0</ValorTotalDeducoes>\r\n" + 
				"	</Cabecalho>\r\n" + 
				"	<RPS xmlns=\"\">\r\n" + 
				"		<ChaveRPS>\r\n" + 
				"			<InscricaoPrestador>39616924</InscricaoPrestador>\r\n" + 
				"			<SerieRPS>BB</SerieRPS>\r\n" + 
				"			<NumeroRPS>4102</NumeroRPS>\r\n" + 
				"		</ChaveRPS>\r\n" + 
				"		<TipoRPS>RPS</TipoRPS>\r\n" + 
				"		<DataEmissao>2018-02-23</DataEmissao>\r\n" + 
				"		<StatusRPS>N</StatusRPS>\r\n" + 
				"		<TributacaoRPS>T</TributacaoRPS>\r\n" + 
				"		<ValorServicos>100</ValorServicos>\r\n" + 
				"		<ValorDeducoes>0</ValorDeducoes>\r\n" + 
				"		<CodigoServico>03204</CodigoServico>\r\n" + 
				"		<AliquotaServicos>0.05</AliquotaServicos>\r\n" + 
				"		<ISSRetido>false</ISSRetido>\r\n" + 
				"		<CPFCNPJTomador>\r\n" + 
				"			<CNPJ>38450278864</CNPJ>\r\n" + 
				"		</CPFCNPJTomador>\r\n" + 
				"		<Discriminacao>Teste</Discriminacao>\r\n" + 
				"	</RPS>\\r\\n\" +\r\n" + 
				"</PedidoEnvioLoteRPS>"));*/
				
      //Teste para Assinar o XML de PedidoEnvioLoteRPS com duas RPSs
		/*System.out.println(AssinarXML.start("PedidoEnvioLoteRPS", "<PedidoEnvioLoteRPS xmlns=\"http://www.prefeitura.sp.gov.br/nfe\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\r\n" + 
				"	<Cabecalho xmlns=\"\" Versao=\"1\">\r\n" + 
				"		<CPFCNPJRemetente>\r\n" + 
				"			<CNPJ>99999997000100</CNPJ>\r\n" + 
				"		</CPFCNPJRemetente>\r\n" + 
				"		<transacao>false</transacao>\r\n" + 
				"		<dtInicio>2018-02-01</dtInicio>\r\n" + 
				"		<dtFim>2018-02-23</dtFim>\r\n" + 
				"		<QtdRPS>2</QtdRPS>\r\n" + 
				"		<ValorTotalServicos>200</ValorTotalServicos>\r\n" + 
				"		<ValorTotalDeducoes>0</ValorTotalDeducoes>\r\n" + 
				"	</Cabecalho>\r\n" + 
				"	<RPS xmlns=\"\">\r\n" + 
				"		<ChaveRPS>\r\n" + 
				"			<InscricaoPrestador>39616924</InscricaoPrestador>\r\n" + 
				"			<SerieRPS>BB</SerieRPS>\r\n" + 
				"			<NumeroRPS>4102</NumeroRPS>\r\n" + 
				"		</ChaveRPS>\r\n" + 
				"		<TipoRPS>RPS</TipoRPS>\r\n" + 
				"		<DataEmissao>2018-02-23</DataEmissao>\r\n" + 
				"		<StatusRPS>N</StatusRPS>\r\n" + 
				"		<TributacaoRPS>T</TributacaoRPS>\r\n" + 
				"		<ValorServicos>100</ValorServicos>\r\n" + 
				"		<ValorDeducoes>0</ValorDeducoes>\r\n" + 
				"		<CodigoServico>03204</CodigoServico>\r\n" + 
				"		<AliquotaServicos>0.05</AliquotaServicos>\r\n" + 
				"		<ISSRetido>false</ISSRetido>\r\n" + 
				"		<CPFCNPJTomador>\r\n" + 
				"			<CNPJ>38450278864</CNPJ>\r\n" + 
				"		</CPFCNPJTomador>\r\n" + 
				"		<Discriminacao>Teste</Discriminacao>\r\n" + 
				"	</RPS>\r\n" +
				"	<RPS xmlns=\"\">\r\n" + 
				"		<ChaveRPS>\r\n" + 
				"			<InscricaoPrestador>39616924</InscricaoPrestador>\r\n" + 
				"			<SerieRPS>BB</SerieRPS>\r\n" + 
				"			<NumeroRPS>4103</NumeroRPS>\r\n" + 
				"		</ChaveRPS>\r\n" + 
				"		<TipoRPS>RPS</TipoRPS>\r\n" + 
				"		<DataEmissao>2018-02-23</DataEmissao>\r\n" + 
				"		<StatusRPS>N</StatusRPS>\r\n" + 
				"		<TributacaoRPS>T</TributacaoRPS>\r\n" + 
				"		<ValorServicos>100</ValorServicos>\r\n" + 
				"		<ValorDeducoes>0</ValorDeducoes>\r\n" + 
				"		<CodigoServico>03204</CodigoServico>\r\n" + 
				"		<AliquotaServicos>0.05</AliquotaServicos>\r\n" + 
				"		<ISSRetido>false</ISSRetido>\r\n" + 
				"		<CPFCNPJTomador>\r\n" + 
				"			<CNPJ>38450278865</CNPJ>\r\n" + 
				"		</CPFCNPJTomador>\r\n" + 
				"		<Discriminacao>Teste</Discriminacao>\r\n" + 
				"	</RPS>\r\n" +
				"</PedidoEnvioLoteRPS>"));*/
	}
}
