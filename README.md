# NFSe_Sao_Paulo

# Resumo
Código em Java para auxiliar no desenvolvimento da assinatura da RPS de São Paulo.

# Descrição
Como o manual da prefeitura de são paulo é meio confuso de entender e para conseguir os exemplos, WSDL e schemas dos serviços é necessário ter em mãos o certificado digital e no meu caso aqui, a empresa só teria o certificado na data da implantação dos serviços de integração, foi necessário pegar um certificado de uma das empresas filiais para poder obter essa informações, o que casou um pouco de atraso no inicio do desenvolvimento por isso estarei disponibilizando também o WSDL, schemas e exemplos.

Com intuito de auxiliar os demais desenvolvedores estou disponibilizando o código utilizado para gerar a TAG assinatura e que assina o XML da RPS.

# Desafio
Desenvolver integração de envio de RPS utilizando BPEL e OSB 12c.

# Dificuldade
Encontrar exemplos e informações necessárias para comunicação e envio das RPS.

# Solução

    1. Middleware
      1. Console (http://localhost:7101/console)
     Primeiro foi necessário configurar Service Key Provider conforme o passo 2 - https://svgonugu.com/2015/03/06/service-bus-12c-outbound-ssl/
     
    2. BPEL
      2.1 DBAdapter
        1 polling para pegar as linhas marcadas como "gerado" para EnvioLoteRPS.
        1 polling para pegar as linhas marcadas como "enviado" para ConsultarNFe.      
        1 polling para pegar as linhas marcadas como "gerado" para CancelarNFe.
      
      2.2 BPEL
        Importante: tive que atribuir o atributo lazyLoading="false" no Composite por causa dos pollings
        Faz a orquestração das informações e atualiza as tabelas necessárias que ficaria disponível para consulta no EBS.

    3. OSB
       3.1 Service Key Provider
          No seu projeto crie uma Service Key Provider e vincule seu certificado.
       3.2 Proxy
          No proxy vincular a Service Key Provider na aba Security.
       3.3 Business
          No business marcar a opção Client Certificate na aba Transport Details.
       3.4 Pipeline
          No pipeline foi necessário um Componente Java Callout e um Replace
          3.4.1 Java Callout
                Method: jar com o códgio em Java
                Arguments: 1º nome da operação, 2 º fn-bea:serialize($body/nfe:TesteEnvioLoteRPSRequest/nfe:MensagemXML/*[1])
                Return: xml
          3.4.2 Replace
                Location: body
                Xpath: ./nfe:TesteEnvioLoteRPSRequest/nfe:MensagemXML
                Value: fn-bea:serialize($xml)
                Replace Option: Replace node contents
                  

# Links úteis
    https://svgonugu.com/2015/03/06/service-bus-12c-outbound-ssl/
    http://www.guj.com.br/t/assinaturas-nfs-e-sao-paulo/135806
    http://www.guj.com.br/t/nfe-prefeitura-de-sao-paulo/295921/21
    http://uanscarvalho.com.br/usando-java-callout-no-osb/
    http://www.javac.com.br/jc/posts/list/106-nfe-assinatura-dos-xmls-de-envio-de-lote-cancelamento-e-inutilizacao-certificado-a1.page
    
    
