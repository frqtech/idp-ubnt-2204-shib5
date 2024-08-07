#!/bin/bash

#title              firstboot.sh
#description        Configuration script for CAFe IDP
#author             Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor   Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date               2024/08/07
#version            5.0.1
#
#changelog          5.0.1 - 2024/08/07 - Adequação para Shibboleth IDP 5.1.3.
#changelog          5.0.0 - 2024/02/29 - Adequação para Shibboleth IDP 5.0.0.

REPOSITORY="https://raw.githubusercontent.com/frqtech/idp-ubnt-2204-shib5/main"
F_LOG="/root/cafe-install.log"

SYSDATE=`date +"%Y-%m-%d %H:%M:%S %z"`
SO_DISTID=`lsb_release -i | awk '{ print $3 }'` 
SO_RELEASE=`lsb_release -r | awk '{ print $2 }'`

FIRSTBOOT="/root/firstboot.sh"

SHIBVERSION="5.1.3"
SHIBTAR="https://shibboleth.net/downloads/identity-provider/archive/${SHIBVERSION}/shibboleth-identity-provider-${SHIBVERSION}.tar.gz"
SHIBSUM="https://shibboleth.net/downloads/identity-provider/archive/${SHIBVERSION}/shibboleth-identity-provider-${SHIBVERSION}.tar.gz.sha256" 
SHIBTAROUT="/root/shibboleth-identity-provider-${SHIBVERSION}.tar.gz"
SHIBSUMOUT="/root/shibboleth-identity-provider-${SHIBVERSION}.tar.gz.sha256"

SRCDIR="/root/shibboleth-identity-provider-${SHIBVERSION}"
SHIBDIR="/opt/shibboleth-idp"


RET=""

function check_integrity {

    cd /root

    wget ${REPOSITORY}/firstboot.sha256 -O /root/firstboot.sha256
    if [ $? -ne 0 ] ; then
        echo "ERRO: Falha no download do arquivo ${REPOSITORY}/firstboot.sha256." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        exit 1
    fi

    sha256sum -c /root/firstboot.sha256
    if [ $? -eq 0 ] ; then
        echo "O arquivo /root/firstboot.sh está integro." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
    else
        echo "ERRO: O arquivo /root/firstboot.sh não está integro." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        exit 1
    fi

}

function setProperty {

    #Based on: https://gist.github.com/kongchen/6748525
    awk -v pat="^$1 ?=" -v value="$1 = $2" '{ if ($0 ~ pat) print value; else print $0; }' $3 > $3.tmp
    mv $3.tmp $3

}

function update_packages {

    echo "INFO - Atualizando pacotes" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    apt update
    apt dist-upgrade -y

}

function config_network {

    echo "INFO - Iniciando a configuração de rede" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

    cat > /etc/netplan/00-installer-config.yaml <<-EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${INTERFACE}:
      dhcp4: no
      addresses: [${IP}/${MASK}]
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses: [${DNS}]
EOF
    
    hostnamectl set-hostname ${HN}.${HN_DOMAIN}
    echo "${IP} ${HN}.${HN_DOMAIN} ${HN}" >> /etc/hosts
    
    echo "INFO - Ajustando Stub DNS" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    
    echo "INFO - Gerando novas chaves para o Servidor SSH" | tee -a ${F_LOG}
    find /etc/ssh -name "ssh_host_*_key*" -exec rm {} \;
    DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical dpkg-reconfigure openssh-server
    echo "INFO - Geracao de chaves finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

    echo "INFO - Aplicando configurações de rede..." | tee -a ${F_LOG}
    netplan apply
    sleep 5
    
    THRESHOLD=3
    TRY=1
    
    while [ ${TRY} -le ${THRESHOLD} ] ; do
        NETTEST=`curl -s ${REPOSITORY}/network.test`
        if [ "${NETTEST}" = "Network test OK." ] ; then
            apt update
            apt dist-upgrade -y
            break
        else
            echo "ATENCAO - Falha no teste de comunicacao de rede - ${TRY}/${THRESHOLD}"
            if [ ${TRY} -lt ${THRESHOLD} ] ; then
                echo "          Nova tentativa em 5 segundos..."
                sleep 5
                netplan apply
            else
                echo "ERRO - Nao foi possivel testar a comunicacao com a rede." | tee -a ${F_LOG}
                echo "       O instalador não pode avançar sem rede." | tee -a ${F_LOG}
                echo "" | tee -a ${F_LOG}
                exit 1
            fi
        fi
        let TRY++
    done
    echo "INFO - Configuração de rede finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

}

function config_firewall {

    echo "INFO - Iniciando configuração de firewall" | tee -a ${F_LOG}

    wget ${REPOSITORY}/firewall/firewall.rules -O /etc/default/firewall
    wget ${REPOSITORY}/firewall/firewall.service -O /etc/systemd/system/firewall.service
    mkdir -p /opt/rnp/firewall/
    wget ${REPOSITORY}/firewall/firewall.sh -O /opt/rnp/firewall/firewall.sh
    
    chmod 755 /opt/rnp/firewall/firewall.sh
    chmod 664 /etc/systemd/system/firewall.service
    systemctl daemon-reload
    systemctl enable firewall.service

    echo "INFO - Configuração de firewall finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

}

function config_ntp {

    echo "INFO - Iniciando configuração de NTP" | tee -a ${F_LOG}

    timedatectl set-ntp no
    apt install -y ntp

    wget ${REPOSITORY}/ntp/ntp.conf -O /etc/ntp.conf

    echo "INFO - Configuração de NTP finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

}

function config_user {

    echo "INFO - Iniciando configuração de usuário" | tee -a ${F_LOG}

    PWDSALT=`openssl rand -base64 4`
    PWDENC=`openssl passwd -6 -salt ${PWDSALT} ${PWDCAFE}`
    useradd cafe -s /bin/bash -p ${PWDENC}

    echo "INFO - Configuração de usuário finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

}

function install_java {

    echo "INFO - Iniciando configuração de Java" | tee -a ${F_LOG}

    echo 'JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto' > /etc/environment
    source /etc/environment
    export JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto
    echo $JAVA_HOME
    
    wget https://corretto.aws/downloads/resources/17.0.10.7.1/B04F24E3.pub -O /tmp/B04F24E3.pub
    gpg --no-default-keyring --keyring /tmp/temp-keyring.gpg --import /tmp/B04F24E3.pub
    gpg --no-default-keyring --keyring /tmp/temp-keyring.gpg --export --output /etc/apt/keyrings/amazon-corretto.gpg
    rm /tmp/temp-keyring.gpg /tmp/B04F24E3.pub /tmp/temp-keyring.gpg~
    
    echo "deb [signed-by=/etc/apt/keyrings/amazon-corretto.gpg] https://apt.corretto.aws stable main" >> /etc/apt/sources.list.d/amazon-corretto.list
    echo "#deb-src [signed-by=/etc/apt/keyrings/amazon-corretto.gpg] https://apt.corretto.aws stable main" >> /etc/apt/sources.list.d/amazon-corretto.list
    
    apt update
    apt install -y java-17-amazon-corretto-jdk

    echo "INFO - Configuração de Java finalizada" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

}

function install_jetty {

    cd /usr/local/src
    wget https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-home/11.0.19/jetty-home-11.0.19.tar.gz
    tar xzvf jetty-home-11.0.19.tar.gz

    ln -nsf jetty-home-11.0.19 jetty-src
    useradd -r -M jetty

    mkdir -p /opt/jetty
    wget ${REPOSITORY}/jetty/start.ini -O /opt/jetty/start.ini

    mkdir /opt/jetty/{tmp,logs,webapps}
    mkdir /var/log/jetty
    chown -R jetty:jetty /opt/jetty /var/log/jetty /usr/local/src/jetty-src

    cat > /etc/default/jetty <<-EOF
JETTY_HOME=/usr/local/src/jetty-src
JETTY_BASE=/opt/jetty
JETTY_PID=/opt/jetty/jetty.pid
JETTY_USER=jetty
JETTY_START_LOG=/var/log/jetty/start.log
TMPDIR=/opt/jetty/tmp
EOF

    cd /etc/init.d
    ln -s /usr/local/src/jetty-src/bin/jetty.sh jetty
    cp /usr/local/src/jetty-src/bin/jetty.service /etc/systemd/system/jetty.service

    #Falta sed do atributo PIDFile no /etc/systemd/system/jetty.service

    setProperty "PIDFile" "/opt/jetty/jetty.pid" "/etc/systemd/system/jetty.service"

    systemctl daemon-reload
    systemctl enable jetty.service

}

function install_shib {

    echo "INFO - Iniciando instalação do Shibboleth IDP" | tee -a ${F_LOG}

    cd /root

    echo "INFO - Download do pacote do Shibboleth IDP" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    wget ${SHIBTAR} -O ${SHIBTAROUT}
    if [ $? -ne 0 ] ; then
        echo "ERRO - Falha no download do arquivo ${SHIBTAR}." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        exit 1
    fi

    echo "INFO - Download do checksum do pacote do Shibboleth IDP" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    wget ${SHIBSUM} -O ${SHIBSUMOUT}
    if [ $? -ne 0 ] ; then
        echo "ERRO - Falha no download do arquivo ${SHIBSUM}." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        exit 1
    fi

    sha256sum -c ${SHIBSUMOUT}
    if [ $? -eq 0 ] ; then
        echo "O arquivo ${SHIBTAROUT} está integro." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
    else
        echo "ERRO: O arquivo ${SHIBTAROUT} não está integro." | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        exit 1
    fi

    if [ -z ${PERSISTENTDIDSALT} ] ; then
        PERSISTENTDIDSALT=`openssl rand -base64 32`
    fi

    if [ -z ${COMPUTEDIDSALT} ] ; then
        COMPUTEDIDSALT=`openssl rand -base64 32`
    fi

    if [ -z ${FTICKSSALT} ] ; then
        FTICKSSALT=`openssl rand -base64 32`
    fi

    echo "INFO - Gerando arquivo de configuração do OpenSSL" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat > /tmp/openssl.cnf <<-EOF
[ req ]
default_bits = 2048 # Size of keys
string_mask = nombstr # permitted characters
distinguished_name = req_distinguished_name
  
[ req_distinguished_name ]
# Variable name   Prompt string
#----------------------   ----------------------------------
0.organizationName = Nome da universidade/organização
organizationalUnitName = Departamento da universidade/organização
emailAddress = Endereço de email da administração
emailAddress_max = 40
localityName = Nome do município (por extenso)
stateOrProvinceName = Unidade da Federação (por extenso)
countryName = Nome do país (código de 2 letras)
countryName_min = 2
countryName_max = 2
commonName = Nome completo do host (incluíndo o domínio)
commonName_max = 64
  
# Default values for the above, for consistency and less typing.
# Variable name   Value
#------------------------------   ------------------------------
0.organizationName_default = ${INITIALS} - ${ORGANIZATION}
emailAddress_default = ${CONTACTMAIL}
organizationalUnitName_default = ${OU}
localityName_default = ${CITY}
stateOrProvinceName_default = ${STATE}
countryName_default = BR
commonName_default = ${HN}.${HN_DOMAIN}
EOF

    echo "INFO - Instalando Shibboleth IDP" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

    tar -zxvf ${SHIBTAROUT}

    cat > /root/idp.property <<-EOF
idp.target.dir=${SHIBDIR}
idp.sealer.password=changeit
idp.keystore.password=changeit
idp.host.name=${HN}.${HN_DOMAIN}
idp.scope=${DOMAIN}
idp.entityID=https://${HN}.${HN_DOMAIN}/idp/shibboleth
EOF

    ${SRCDIR}/bin/install.sh --propertyFile /root/idp.property

    /opt/shibboleth-idp/bin/module.sh -e idp.authn.Password

    echo "INFO - Gerando certificado digital para o Shibboleth IDP" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cd ${SHIBDIR}/credentials/
    rm -f idp*
    openssl genrsa -out idp.key 2048
    openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key idp.key -set_serial 00 -config /tmp/openssl.cnf -out idp.crt
    echo "Certificado Shibboleth" | tee -a ${F_LOG}
    openssl x509 -in ${SHIBDIR}/credentials/idp.crt -text -noout | tee -a ${F_LOG}

    echo "INFO - Obtendo arquivos de configuração estáticos" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    wget ${REPOSITORY}/shibboleth/conf/attribute-filter.xml -O ${SHIBDIR}/conf/attribute-filter.xml
    wget ${REPOSITORY}/shibboleth/conf/attribute-resolver.xml -O ${SHIBDIR}/conf/attribute-resolver.xml
    wget ${REPOSITORY}/shibboleth/conf/metadata-providers.xml -O ${SHIBDIR}/conf/metadata-providers.xml
    wget ${REPOSITORY}/shibboleth/conf/saml-nameid.xml -O ${SHIBDIR}/conf/saml-nameid.xml
    wget ${REPOSITORY}/shibboleth/conf/admin/admin.properties -O ${SHIBDIR}/conf/admin/admin.properties
    wget ${REPOSITORY}/shibboleth/conf/attributes/brEduPerson.xml -O ${SHIBDIR}/conf/attributes/brEduPerson.xml
    wget ${REPOSITORY}/shibboleth/conf/attributes/default-rules.xml -O ${SHIBDIR}/conf/attributes/default-rules.xml
    wget ${REPOSITORY}/shibboleth/conf/attributes/schac.xml -O ${SHIBDIR}/conf/attributes/schac.xml

    echo "INFO - Configurando ldap.properties" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat > ${SHIBDIR}/conf/ldap.properties <<-EOF
# LDAP authentication (and possibly attribute resolver) configuration
# Note, this doesn't apply to the use of JAAS authentication via LDAP

## Authenticator strategy, either anonSearchAuthenticator, bindSearchAuthenticator, directAuthenticator, adAuthenticator
idp.authn.LDAP.authenticator                       = bindSearchAuthenticator

## Connection properties ##
idp.authn.LDAP.ldapURL                             = ${LDAPSERVERPROTO}${LDAPSERVER}:${LDAPSERVERPORT}
idp.authn.LDAP.useStartTLS                         = false
# Time in milliseconds that connects will block
idp.authn.LDAP.connectTimeout                      = PT3S
# Time in milliseconds to wait for responses
idp.authn.LDAP.responseTimeout                     = PT3S
# Connection strategy to use when multiple URLs are supplied, either ACTIVE_PASSIVE, ROUND_ROBIN, RANDOM
#idp.authn.LDAP.connectionStrategy                 = ACTIVE_PASSIVE

## SSL configuration, either jvmTrust, certificateTrust, or keyStoreTrust
idp.authn.LDAP.sslConfig                           = certificateTrust
## If using certificateTrust above, set to the trusted certificate's path
idp.authn.LDAP.trustCertificates                   = %{idp.home}/credentials/ldap-server.crt
## If using keyStoreTrust above, set to the truststore path
#idp.authn.LDAP.trustStore                         = %{idp.home}/credentials/ldap-server.truststore

## Return attributes during authentication
idp.authn.LDAP.returnAttributes                    = ${LDAPATTR}

## DN resolution properties ##

# Search DN resolution, used by anonSearchAuthenticator, bindSearchAuthenticator
# for AD: CN=Users,DC=example,DC=org
idp.authn.LDAP.baseDN                              = ${LDAPDN}
idp.authn.LDAP.subtreeSearch                       = ${LDAPSUBTREESEARCH}
idp.authn.LDAP.userFilter                          = (${LDAPATTR}={user})
# bind search configuration
# for AD: idp.authn.LDAP.bindDN=adminuser@domain.com
idp.authn.LDAP.bindDN                              = ${LDAPUSER}

# Format DN resolution, used by directAuthenticator, adAuthenticator
# for AD use idp.authn.LDAP.dnFormat=%s@domain.com
idp.authn.LDAP.dnFormat                            = ${LDAPFORM}

# pool passivator, either none, bind or anonymousBind
#idp.authn.LDAP.bindPoolPassivator                 = none

# LDAP attribute configuration, see attribute-resolver.xml
# Note, this likely won't apply to the use of legacy V2 resolver configurations
idp.attribute.resolver.LDAP.ldapURL                = %{idp.authn.LDAP.ldapURL}
idp.attribute.resolver.LDAP.connectTimeout         = %{idp.authn.LDAP.connectTimeout:PT3S}
idp.attribute.resolver.LDAP.responseTimeout        = %{idp.authn.LDAP.responseTimeout:PT3S}
idp.attribute.resolver.LDAP.connectionStrategy     = %{idp.authn.LDAP.connectionStrategy:ACTIVE_PASSIVE}
idp.attribute.resolver.LDAP.baseDN                 = %{idp.authn.LDAP.baseDN:undefined}
idp.attribute.resolver.LDAP.bindDN                 = %{idp.authn.LDAP.bindDN:undefined}
idp.attribute.resolver.LDAP.useStartTLS            = %{idp.authn.LDAP.useStartTLS:true}
idp.attribute.resolver.LDAP.trustCertificates      = %{idp.authn.LDAP.trustCertificates:undefined}
idp.attribute.resolver.LDAP.searchFilter           = (${LDAPATTR}=\$resolutionContext.principal)
idp.attribute.resolver.LDAP.multipleResultsIsError = false

# LDAP pool configuration, used for both authn and DN resolution
#idp.pool.LDAP.minSize                             = 3
#idp.pool.LDAP.maxSize                             = 10
#idp.pool.LDAP.validateOnCheckout                  = false
#idp.pool.LDAP.validatePeriodically                = true
#idp.pool.LDAP.validatePeriod                      = PT5M
#idp.pool.LDAP.validateDN                          =
#idp.pool.LDAP.validateFilter                      = (objectClass=*)
#idp.pool.LDAP.prunePeriod                         = PT5M
#idp.pool.LDAP.idleTime                            = PT10M
#idp.pool.LDAP.blockWaitTime                       = PT3S 
EOF

#
# SHIB - secrets.properties
#

    echo "INFO - Configurando secrets.properties" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat  > ${SHIBDIR}/credentials/secrets.properties <<-EOF
# Access to internal AES encryption key
idp.sealer.storePassword = changeit
idp.sealer.keyPassword = changeit

# Default access to LDAP authn and attribute stores.
idp.authn.LDAP.bindDNCredential              = ${LDAPPWD}
idp.attribute.resolver.LDAP.bindDNCredential = %{idp.authn.LDAP.bindDNCredential:undefined}

# Salt used to generate persistent/pairwise IDs, must be kept secret
idp.persistentId.salt  = ${PERSISTENTDIDSALT}

idp.cafe.computedIDsalt = ${COMPUTEDIDSALT}
EOF

#
# SHIB - idp-properties
#
    echo "INFO - Configurando idp.properties" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat  > ${SHIBDIR}/conf/idp.properties <<-EOF
idp.searchForProperties= true

idp.additionalProperties= /credentials/secrets.properties

idp.entityID= https://${HN}.${HN_DOMAIN}/idp/shibboleth

idp.scope= ${DOMAIN}
 
idp.csrf.enabled=true

idp.sealer.storeResource=%{idp.home}/credentials/sealer.jks
idp.sealer.versionResource=%{idp.home}/credentials/sealer.kver

idp.signing.key=%{idp.home}/credentials/idp.key
idp.signing.cert=%{idp.home}/credentials/idp.crt
idp.encryption.key=%{idp.home}/credentials/idp.key
idp.encryption.cert=%{idp.home}/credentials/idp.crt

idp.encryption.config=shibboleth.EncryptionConfiguration.GCM

idp.trust.signatures=shibboleth.ExplicitKeySignatureTrustEngine

idp.storage.htmlLocalStorage=true

idp.session.trackSPSessions=true
idp.session.secondaryServiceIndex=true

idp.bindings.inMetadataOrder=false

idp.ui.fallbackLanguages=pt-br,en

idp.fticks.federation = CAFE
idp.fticks.algorithm = SHA-256
idp.fticks.salt = ${FTICKSSALT}
idp.fticks.loghost= localhost
idp.fticks.logport= 514

idp.audit.shortenBindings=true

#idp.loglevel.idp = DEBUG
#idp.loglevel.ldap = DEBUG
#idp.loglevel.messages = DEBUG
#idp.loglevel.encryption = DEBUG
#idp.loglevel.opensaml = DEBUG
#idp.loglevel.props = DEBUG
#idp.loglevel.httpclient = DEBUG
EOF

#
# SHIB - saml-nameid.properties
#
    echo "INFO - Configurando saml-nameid.properties" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat  > ${SHIBDIR}/conf/saml-nameid.properties <<-EOF
idp.persistentId.sourceAttribute = ${LDAPATTR}
idp.persistentId.encoding = BASE32
EOF

#
# SHIB - idp-metadata.xml
#

    echo "INFO - Configurando idp-metadata.xml" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cp ${SHIBDIR}/credentials/idp.crt /tmp/idp.crt.tmp
    sed -i '$ d' /tmp/idp.crt.tmp
    sed -i 1d /tmp/idp.crt.tmp
    CRT=`cat /tmp/idp.crt.tmp`
    rm -rf /tmp/idp.crt.tmp
    cat > /opt/shibboleth-idp/metadata/idp-metadata.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>

<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:shibmd="urn:mace:shibboleth:metadata:1.0"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
    xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
    xmlns:xrd="http://docs.oasis-open.org/ns/xri/xrd-1.0"
    xmlns:pyff="http://pyff.io/NS"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    entityID="https://${HN}.${HN_DOMAIN}/idp/shibboleth">

    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">
        <Extensions>
            <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
            <mdui:UIInfo>
                <mdui:DisplayName xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:DisplayName>
                <mdui:DisplayName xml:lang="pt-br">${INITIALS} - ${ORGANIZATION}</mdui:DisplayName>
                <mdui:Description xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:Description>
                <mdui:Description xml:lang="pt-br">${INITIALS} - ${ORGANIZATION}</mdui:Description>
                <mdui:InformationURL xml:lang="pt-br">http://www.${DOMAIN}/</mdui:InformationURL>
            </mdui:UIInfo>
        </Extensions>
        <KeyDescriptor>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
${CRT}
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/ArtifactResolution" index="1"/>
        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/ArtifactResolution" index="2"/>

        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/SLO"/>

        <NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>
        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>

        <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://${HN}.${HN_DOMAIN}/idp/profile/Shibboleth/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SSO"/>
    </IDPSSODescriptor>

    <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">
        <Extensions>
            <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
        </Extensions>
        <KeyDescriptor>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
${CRT}
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/AttributeQuery"/>
    </AttributeAuthorityDescriptor>

    <ContactPerson contactType="technical">
        <GivenName>${CONTACTGIVEN}</GivenName>
        <SurName>${CONTACTSUR}</SurName>
        <EmailAddress>mailto:${CONTACTMAIL}</EmailAddress>
    </ContactPerson>

    <ContactPerson xmlns:remd="http://refeds.org/metadata" contactType="other" remd:contactType="http://refeds.org/metadata/contactType/security">
        <GivenName>${CONTACTGIVEN}</GivenName>
        <SurName>${CONTACTSUR}</SurName>
        <EmailAddress>mailto:${CONTACTMAIL}</EmailAddress>
    </ContactPerson>

</EntityDescriptor>
EOF

#
# SHIB - access-control.xml
#
    echo "INFO - Configurando access-control.xml" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat > /opt/shibboleth-idp/conf/access-control.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:context="http://www.springframework.org/schema/context"
    xmlns:util="http://www.springframework.org/schema/util"
    xmlns:p="http://www.springframework.org/schema/p"
    xmlns:c="http://www.springframework.org/schema/c"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                        http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
                        http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd" default-init-method="initialize" default-destroy-method="destroy">

    <util:map id="shibboleth.AccessControlPolicies">

        <entry key="AccessByIPAddress">
            <bean id="AccessByIPAddress" parent="shibboleth.IPRangeAccessControl" p:allowedRanges="#{ {'127.0.0.1/32', '::1/128', '${IP}/32'} }" />
        </entry>

    </util:map>

</beans>
EOF

    echo "INFO - Ativando plugin Nashorn" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    mkdir /opt/shibboleth-idp/credentials/net.shibboleth.idp.plugin.nashorn
    wget ${REPOSITORY}/shibboleth/credentials/nashorn-truststore.asc -O ${SHIBDIR}/credentials/net.shibboleth.idp.plugin.nashorn/truststore.asc
    /opt/shibboleth-idp/bin/plugin.sh -I net.shibboleth.idp.plugin.nashorn

    # Se LDAP usa SSL, pega certificado e adiciona no keystore
    if [ ${LDAPSERVERSSL} -eq 1 ] ; then
        echo "INFO - Configurando Certificados LDAPS" | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        openssl s_client -showcerts -connect ${LDAPSERVER}:${LDAPSERVERPORT} < /dev/null 2> /dev/null | openssl x509 -outform PEM > /opt/shibboleth-idp/credentials/ldap-server.crt
        /usr/lib/jvm/java-17-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /usr/lib/jvm/java-17-amazon-corretto/lib/security/cacerts -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit
        /usr/lib/jvm/java-17-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /opt/shibboleth-idp/credentials/ldap-server.truststore -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit
        sed -i -e 's/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\"/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\" trustFile=\"%{idp.attribute.resolver.LDAP.trustCertificates}\"/' /opt/shibboleth-idp/conf/attribute-resolver.xml
    fi

    # Corrige permissões
    echo "INFO - Corigindo permissões de diretórios" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    chown -R jetty:jetty ${SHIBDIR}/{credentials,logs,metadata}

    # Configura contexto no Jetty
    echo "INFO - Configurando contexto Jetty" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    cat > /opt/jetty/webapps/idp.xml <<-EOF
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "http://www.eclipse.org/jetty/configure.dtd">
<Configure class="org.eclipse.jetty.webapp.WebAppContext">
  <Set name="war">${SHIBDIR}/war/idp.war</Set>
  <Set name="contextPath">/idp</Set>
  <Set name="extractWAR">false</Set>
  <Set name="copyWebDir">false</Set>
  <Set name="copyWebInf">true</Set>
  <Set name="persistTempDirectory">false</Set>
</Configure>
EOF

}

function install_apache {

    echo "INFO - Instalando Apache" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    apt update
    apt install -y apache2 libapache2-mod-xforward
    wget ${REPOSITORY}/apache/security.conf -O /etc/apache2/conf-available/security.conf
    cat > /etc/apache2/sites-available/01-idp.conf <<-EOF
<VirtualHost ${IP}:80>

    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    Redirect permanent "/" "https://${HN}.${HN_DOMAIN}/"

</VirtualHost>

<VirtualHost ${IP}:443>
 
    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    SSLEngine On
    SSLProtocol -all +TLSv1.1 +TLSv1.2
    SSLCipherSuite ALL:+HIGH:+AES256:+GCM:+RSA:+SHA384:!AES128-SHA256:!AES256-SHA256:!AES128-GCM-SHA256:!AES256-GCM-SHA384:-MEDIUM:-LOW:!SHA:!3DES:!ADH:!MD5:!RC4:!NULL:!DES
    SSLHonorCipherOrder on
    SSLCompression off
    SSLCertificateKeyFile /etc/ssl/private/chave-apache.key
    SSLCertificateFile /etc/ssl/certs/certificado-apache.crt

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port 443
    ProxyPass /idp http://localhost:8080/idp
    ProxyPassReverse /idp http://localhost:8080/idp

    Redirect permanent "/" "https://${URL}/"

</VirtualHost>
EOF

    # Chave e Certificado Apache
    openssl genrsa -out /etc/ssl/private/chave-apache.key 2048
    openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key /etc/ssl/private/chave-apache.key -set_serial 00 \
        -config /tmp/openssl.cnf -out /etc/ssl/certs/certificado-apache.crt
    echo "Certificado Apache" | tee -a ${F_LOG}
    openssl x509 -in /etc/ssl/certs/certificado-apache.crt -text -noout | tee -a ${F_LOG}
    chown root:ssl-cert /etc/ssl/private/chave-apache.key /etc/ssl/certs/certificado-apache.crt
    chmod 640 /etc/ssl/private/chave-apache.key
    a2dissite 000-default.conf
    a2enmod ssl headers proxy_http
    a2ensite 01-idp.conf
    systemctl restart apache2

}

function configure_layout {

    echo "INFO - Configurando layout personalizado" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

    #Copiando arquivo para personalizacao
    mkdir /tmp/shib-idp
    cd /tmp/shib-idp
    wget ${REPOSITORY}/shibboleth/layout/pacote-personalizacao-layout-4.1.tar.gz -O /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz
    tar -zxvf /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz
    mkdir ${SHIBDIR}/edit-webapp/api
    cp /tmp/shib-idp/views/*.vm ${SHIBDIR}/views/
    cp /tmp/shib-idp/views/client-storage/*.vm ${SHIBDIR}/views/client-storage/
    cp /tmp/shib-idp/edit-webapp/css/*.css ${SHIBDIR}/edit-webapp/css/
    cp -R /tmp/shib-idp/edit-webapp/api/* ${SHIBDIR}/edit-webapp/api/
    cp -R /tmp/shib-idp/edit-webapp/images/* ${SHIBDIR}/edit-webapp/images/
    cp /tmp/shib-idp/messages/*.properties ${SHIBDIR}/messages/

    #Configurando mensagens
    setProperty "idp.login.username.label" "${MSG_AUTENTICACAO}" "${SHIBDIR}/messages/messages_pt_BR.properties"
    setProperty "idp.url.password.reset" "${MSG_URL_RECUPERACAO_SENHA}" "${SHIBDIR}/messages/messages_pt_BR.properties"

    #Atualizacao do war
    echo "" 
    echo "INFO - Build/update WAR"  | tee -a ${F_LOG}
    echo ""  | tee -a ${F_LOG}
    ${SHIBDIR}/bin/build.sh

}

function configure_fticks {

    echo "Configurando FTICKS" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
    apt update
    apt install -y rsyslog filebeat
    cat > /etc/rsyslog.conf <<-EOF
#  /etc/rsyslog.conf    Configuration file for rsyslog.
#
#                       For more information see
#                       /usr/share/doc/rsyslog-doc/html/rsyslog_conf.html
#
#  Default logging rules can be found in /etc/rsyslog.d/50-default.conf

#################
#### MODULES ####
#################

#module(load="imuxsock") # provides support for local system logging
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
#\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Filter duplicated messages
\$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
\$FileOwner syslog
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022
\$PrivDropToUser syslog
\$PrivDropToGroup syslog

#
# Where to place spool and state files
#
\$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
\$IncludeConfig /etc/rsyslog.d/*.conf
EOF

    cat > /etc/rsyslog.d/01-fticks.conf <<-EOF
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" /var/log/fticks.log
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" ~
EOF

    touch /var/log/fticks.log
    chmod 0640 /var/log/fticks.log
    chown syslog:adm /var/log/fticks.log
    systemctl restart rsyslog
    cat > /etc/filebeat/filebeat.yml <<-EOF
#============================ Filebeat inputs ================================

filebeat.inputs:

- type: log

  enabled: true

  paths:
    - /var/log/fticks.log

#============================= Filebeat modules ==============================

filebeat.config.modules:

  path: \${path.config}/modules.d/*.yml

  reload.enabled: false

#----------------------------- Logstash output --------------------------------

output.logstash:
  hosts: ["estat-ls.cafe.rnp.br:5044"]

#================================ Processors ==================================

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
EOF

    systemctl restart filebeat
    systemctl enable filebeat

    cat > /etc/logrotate.d/fticks <<-EOF
/var/log/fticks.log {
    su root root
    create 0640 syslog adm
    daily
    rotate 180
    compress
    nodelaycompress
    dateext
    missingok
    postrotate
        systemctl restart rsyslog
    endscript
}
EOF

}

function configure_fail2ban {

    echo "INFO - Configurando Fail2ban" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    apt install -y fail2ban
    cat > /etc/fail2ban/filter.d/shibboleth-idp.conf <<-EOF
# Fail2Ban filter for Shibboleth IDP
#
# Author: rui.ribeiro@cafe.rnp.br
#
[INCLUDES]
before          = common.conf

[Definition]
_daemon         = jetty
failregex       = <HOST>.*Login by.*failed
EOF

    cat > /etc/fail2ban/jail.local <<-EOF
[shibboleth-idp]
enabled = true
filter = shibboleth-idp
port = all
banaction = iptables-allports
logpath = /opt/shibboleth-idp/logs/idp-process.log
findtime = 300
maxretry = 5
EOF

}

function main {

    echo "" | tee -a ${F_LOG}
    echo "------------------------------------------------------------" | tee -a ${F_LOG}
    echo "          RNP - Rede Nacional de Ensino e Pesquisa          " | tee -a ${F_LOG}
    echo "            CAFe - Comunidade Acadêmica Federada            " | tee -a ${F_LOG}
    echo "------------------------------------------------------------" | tee -a ${F_LOG}
    echo "Script: firstboot.sh                Versao: 5.0.0 10/03/2024" | tee -a ${F_LOG}
    echo "------------------------------------------------------------" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}
    echo "SYSDATE = ${SYSDATE}" | tee -a ${F_LOG}
    echo "SO_DISTID = ${SO_DISTID}" | tee -a ${F_LOG}
    echo "SO_RELEASE = ${SO_RELEASE}" | tee -a ${F_LOG}
    echo "" | tee -a ${F_LOG}

    if [ -n ${IFILE} ] ; then
        if [ -f ${IFILE} ] ; then
            . ${IFILE}
        else
            echo "ERRO - O arquivo de variáveis informado não existe" | tee -a ${F_LOG}
            echo "" | tee -a ${F_LOG}
            exit 1
        fi
    else
        echo "INFO - Não informado arquivo de variáveis" | tee -a ${F_LOG}
    fi

    check_integrity
    update_packages
#    config_network
    config_firewall
    config_ntp
    config_user
    install_java
    install_jetty
    install_shib
    install_apache
    configure_layout
    configure_fticks
    configure_fail2ban

}

ami=`whoami`
IFILE=""

#Tratamento de parâmentros
while getopts "f:" OPT; do
    case "$OPT" in
        "f") IFILE=${OPTARG} ;;
        "?") exit -1;;
    esac
done

if [ "$ami" == "root" ] ; then
    main
else
    echo "ERROR - Voce deve executar este script com permissao de root." | tee -a ${F_LOG}
fi
