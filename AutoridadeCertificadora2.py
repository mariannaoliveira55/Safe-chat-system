#!/usr/bin/env python
# coding: utf-8

# In[4]:


import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os, json


# In[5]:


pasta_ca = 'AutoridadeCertificadora'
ficheiro_cert = os.path.join(pasta_ca,"certificado_raiz.pem")
ficheiro_chave = os.path.join(pasta_ca,"chavepriv_raiz.pem")
revogados = os.path.join(pasta_ca,"certificados_revogados.json")

class AutoridadeCertificadora:

    def __init__(self):
        #self.criar_ca_raiz()
        self.chave_priv = serialization.load_pem_private_key(open(ficheiro_chave, "rb").read(), password=None)
        self.cert_raiz = x509.load_pem_x509_certificate(open(ficheiro_cert, "rb").read())
        self.revogados = self.ler_ficheiros_revogados()

    def criar_ca_raiz(self):
        os.makedirs(pasta_ca, exist_ok=True)
        chave = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = self.issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AutoridadeCertRaiz")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.issuer)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(chave, hashes.SHA256())
        )

        with open(ficheiro_chave, "wb") as f:
            f.write(chave.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(ficheiro_cert, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("CA criada com sucesso!")

    def emitir_certificado(self, nome, guardar=False):
         chave = rsa.generate_private_key(public_exponent=65537, key_size=4096)
         subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)])
         cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.issuer)
            .public_key(chave.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.chave_priv, hashes.SHA256())
         )
         nova_chave_priv = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
         novo_cert = cert.public_bytes(serialization.Encoding.PEM)
        
         if guardar:
             with open(f"{nome}_chave.pem", "wb") as f:
                f.write(nova_chave_priv)
             with open(f"{nome}_cert.pem", "wb") as f:
                f.write(novo_cert)
                 
         print(f"Certificado para {nome} criada com sucesso!")
         return nova_chave_priv, novo_cert

    def ler_ficheiros_revogados(self):
        if os.path.exists(revogados):
           with open(revogados) as f:
               return set(json.load(f))
        else:
            return set()

    def pem_para_bytes(self,ficheiro_pem):
        with open(ficheiro_pem, "rb") as f:
            f_bytes = f.read()
        return f_bytes

    def revogar_certificado(self, cert):
        if type(cert) == str:
           cert = self.pem_para_bytes(cert)
        cert = x509.load_pem_x509_certificate(cert)
        self.revogados.add(cert.serial_number)
        with open(revogados, "w") as f:
            json.dump(list(self.revogados), f)
        
    def is_revogado(self,cert):
        if type(cert) == str:
           cert = self.pem_para_bytes(cert)
        cert = x509.load_pem_x509_certificate(cert)
        return cert.serial_number in self.revogados

    def is_identidade_valida(self,cert,nome_esperado):
        if type(cert) == str:
           cert = self.pem_para_bytes(cert)
        cert = x509.load_pem_x509_certificate(cert)
        subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return subject == nome_esperado

    def is_autentico(self, cert, cert_CA):
        if type(cert) == str:
           cert = self.pem_para_bytes(cert)
        if type(cert_CA) == str:
           cert_CA = self.pem_para_bytes(cert_CA)
        cert = x509.load_pem_x509_certificate(cert)
        cert_CA = x509.load_pem_x509_certificate(cert_CA)
        ca_pubkey = cert_CA.public_key()
        try:
           # Verifica se o certificado foi assinado pela CA (assinatura válida)
            ca_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,  # Parte do certificado que foi assinada
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
            )
            return True
        except Exception as e:
            print(f"Certificado inválido ou não assinado por CA confiável: {e}")
            return False

    def is_valido(self, certificado):
        if type(certificado) == str:
           certificado = self.pem_para_bytes(certificado)
        certificado = x509.load_pem_x509_certificate(certificado)
        agora = datetime.datetime.utcnow()
        return certificado.not_valid_before <= agora <= certificado.not_valid_after
         

