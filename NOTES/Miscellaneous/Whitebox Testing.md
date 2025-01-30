### WHITEBOX TESTING

#### NODEJS

```bash
#HTTP Routing + Export functions (ROUTING / GET / POST) + Dependencies
.use(
.get(
.post
.exports.

package.json

#Sources (GET - URL / BODY / ROUTE / PATH / HEADERS / FILES)
req.query.
querystring.parse(
req.body.
req.params --> /:id  --> 'id' is a routing parameter
req.path
req.header
req.file

#Authentication / Authorization
req.session.  # -> Look for unprotected endpoints / weak cryptography / skippable auth logic
req.params    # -> look for uncontrolled routing parameters in API calls --> object IDORs
req.session.userId # -> Controllable session IDs --> broken authorization?
[Check CSRF tokens in authenticated requests, check JWT token]

#SQL Injections --> require('pg').query() usage is safe --> check if require('pg') is used for querying
.query(
dg.get(
sql
" +
'"
'${

#OS Injection
require('child_process')
.execSync( --> wrapping input in single quotes doesnt work --> the safe option is spawnSync( 

#JS Code execution  --> also used with improper deserialization
eval(
require('fs').writeFileSync('/tmp/maliciousfile','')  --> Write file PoC
require('child_process').exec('id > /tmp/proof')      --> RCE PoC

#XXE Injection
libxmljs.parse  + noent: true
<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><t>&e;</t> --> LFI PoC

#Prototype pollution
] =  # -> Look for anyObject[CONTROL_VALUE1] = CONTROL_VALUE2  --> also dot notation instead of []
     # -> Inject '__proto__' string in the property (CONTROL_VALUE1)
     # -> Inject {[any_property]: 'whatever_you_want'};  in CONTROL_VALUE2
     # -> Every other object with 'any_property' implemented will be poisoned
     # -> Can you use this to hijack the application flow? Gain execution?

#LFI  --> with no express.static in the export used
.readFile(
.readFileSync(

#Sensitive exposure
secret: 
[missing error handling]
[stack traces and verbose errors]

#Race conditions
readFile( + fs.unlinkSync( outside functional block  --> files get unlinked before reading?

#Open redirects
.redirect(
```

#### PYTHON

```bash
#HTTP Routing + Dependencies
.route(
requirements.txt

#Sources (GET / POST / BOTH / FILES / HEADERS / USERS / PATH)
request.args / request.GET
request.form
request.values
request.files
request.headers / request.META
request.user
path('
any_function(self, [parameter-here])

#Authentication and Authorization
[weak cryptography / guessable session IDs / logic errors in login functions / unprotected endpoints]
[exposed routes to any user / controllable API route IDs]
[missing CSRF protection for authenticated functions]

session(
User.has_perm(
is_authenticated
admin

#SQL Injection --> unsafe quoted placeholders + concatenation --> use ?, :[param], %s
.cursor(
.execute(
sql
query

#OS Injection -> shell=False is safe when using subprocess
system(
popen(
.call(
.run(
.check_call(
.check_output

#Deserialization  --> Use JSON to serialize data
pickle.loads(
yaml.load
.FullLoader / YAML Loader

#XXE Injection  --> lxml libraries? use native or set resolve_entities=False in etree.XMLParser
etree.XMLParser(
etree.fromstring(

#LFI  --> without .GetFullPath() or .GetFileName() used to avoid directory escape
System.IO.Path.Combine(

#SSTI  --> wrap inputs in ${} or {{}}, avoid concatenation!
Jinja2.from_string(
Template(
template.Template(
.render(
.generate(

#Exposed Flask debug and secret
secret
WERKZEUG_DEBUG_PIN=off
FLASK_DEBUG=1
```

#### JAVA

```bash
#HTTP Routing + Servlets (GET / POST / ROUTE) + Dependencies
[search for public/private classes]
@RequestMapping( --> public classes --> Controller keywords
"/

.doaction(
.dopost(
.doget(

#Sources (GET / POST / ROUTING / HEADERS)
.getParameter(  +  String [name] --> in public classes

@Path("/roles/{param_here}")  --> @PathParam(

.getHeader(

#Authentication / Authorization
.authenticated(
.permitAll(
.hasRole(
authorizeRequests(

[weak cryptography / guessable session IDs / logic errors in login functions / unprotected endpoints]
[exposed routes to any user / controllable API route IDs]
[CSRF protection for authenticated functions]

#File Upload  --> no .getName() or extension validation, no content check.
FileUtils.copyFile(
ProcessFile
.copyInputStreamToFile

#NoSQL / SQL Injections
{{{  --> elasticsearch escapable JSON queries --> use {{

.createStatment(  --> use prepareStatment() instead, avoid concatenation, use '?'
.executequery(
" +

#XXE Injection --> no .setfeature to FALSE --> check if the parser allows default XXE
ProcessXML
.newSAXParser(
XMLInputFactory.
DocumentBuilderFactory --> .newDocumentBuilder(

FileInputStream(  --> you can control XML files here

#OS Injection --> avoid runtime execution when possible --> example: .FileList for listings
.getRuntime(
.exec(

#SSRF --> no restrictions? can access file:// or other network protocols
new URL(  --> parameter inside with no validation, called with .openConnection / buffer reads

#Deserialization --> no setObjectInputFilter()? always opt for JSON serialization
.readObject(  --> an InputStream you control ends up in here
Serializable

#Open Redirects
redirect(
```

#### .NET

```bash
#HTTP Routing (GET / POST / ROUTE) + Dependencies
[Route("
[HttpPost]
[HttpGet]
[public classes]

#Sources (GET / POST / Headers)
Request.Query
Request.QueryString
String [name] --> in routing classes
Request.Headers

#Authentication / Authorization / CSRF
[weak cryptography / guessable session IDs / logic errors in login functions / unprotected endpoints]
[exposed routes to any user / controllable API route IDs]
[CSRF protection for authenticated functions]

TokenValidationParameters --> see how JWT is implemented

[Authorize]
[AllowAnonymous] defined outside class overrides any [Authorize]
HttpContext.User

[ValidateAntiForgeryToken]

#SQL Injection --> concatenated '{variable}'
SqlQuery(
SqlCommand(
FromSql(

#OS Injection --> shell reference inside? Concatenation with {variable}
.ProcessStartInfo(
.Start(

#XXE Injection --> XmlSecureResolver is better
OpenReadStream(
XmlUrlResolver(

#SSTI --> string concatenation with {variable} --> safe option is Engine.Razor.RunCompile() with @var
ViewBag.RenderedTemplate
Razor.Parse(
@{System.Diagnostics.Process.Start("touch /tmp/malicious.sh"); }'

#Log injection --> allows to poison the log files
.LogInformation(

#Deserialization --> ysoserial.net for exploits, use JSON/XML for deserialize! use BinaryReader()!
[Serializable]
BinaryFormatter( --> this is insecure
.ReadAllBytes( --> is a source here?
Deserialize( --> does the inputstream ends up here?

#LFI --> no .GetFullPath() or .GetFileName() employed?
System.IO.Path.Combine(

#File Upload --> missing .GetFileName() or .GetExtension() or other validations?
File.exists(
.WriteLine(
.CreateText(

#Open redirects --> use Url.IsLocalUrl() to prevend open redirection
WebRequest.Create(
Redirect(
```

#### PHP

```bash
#HTTP Routing 
@Route( / @Method(

#Authentication / Authorization
missing @Security( in sensitive routes --> broken authentication
$_SESSION[ --> is this variable checked for access? CSRF tokens?
isCsrfTokenValid(
any type juggling vulnerabilities?

#Sources / FILES
$_GET[
$_POST[
$_FILES[
request->get(
request->post(

#SQL Injection --> use mysqli->prepare( + ? insertion
query->get(
CreateNativeQuery( --> '%variable%' insertion

#Unrestricted file download --> without basename(
@file_get_contents(  --> $user_controlled_var

#Deserialization
unserialize() + magic_methods --> use PHPGCC

#XXE injection
loadXML(
libxml_disable --> are entity_loader(true)?
XMLReader::read()
DOMDocument::loadXML()
DOMDocument::loadHTML()
simplexml_load_string()
simplexml_load_file()

#LFI
include_once(
include(
require(
require_once( 
```
