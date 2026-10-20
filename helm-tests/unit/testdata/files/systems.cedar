// Systems with a client certificate of the Example client CA. Write each subject as in
// trustedSubjects.yaml, but with every backslash doubled (\\), as Cedar strings require.
permit (
  principal == Subject::"CN=billing,OU=Clients,O=Example Corp,C=DE",
  action in [Action::"GET", Action::"POST"],
  resource
) when {
  context.type == "x509" &&
  context.issuer == "CN=Example Client CA,O=Example Corp,C=DE" &&
  context.path like "/cmk/v1/*"
};
// Read-only access for the reporting service and for the billing service in us10.
permit (
  principal,
  action == Action::"GET",
  resource
) when {
  principal in [
    Subject::"CN=reporting,OU=Clients,O=Example Corp,C=DE",
    Subject::"CN=billing,OU=Clients,O=Example\\, Inc.,C=US"
  ] &&
  context.type == "x509" &&
  context.issuer == "CN=Example Client CA,O=Example Corp,C=DE" &&
  context.path like "/cmk/v1/*"
};
// A technical user with tokens of a statically trusted identity provider
// (config.jwt.providers), identified by the sub claim of its tokens.
permit (
  principal == Subject::"automation-client",
  action in [Action::"GET", Action::"POST", Action::"DELETE"],
  resource
) when {
  context.type == "jwt" &&
  context.issuer == "https://idp.example.com/realms/automation" &&
  context.path like "/cmk/v1/*"
};
