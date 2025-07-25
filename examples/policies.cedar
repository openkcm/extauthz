/////////////////////////////////////////
// Technical system based on x509
permit (
	principal == Subject::"CN=TechSys01, OU=MyUnit, O=MyOrg, C=DE",
	action in [Action::"GET", Action::"POST", Action::"DELETE"],
	resource is Route
) when {
	context.type == "x509"
	&& context.route like "myorg.com/api/*"
	&& context.issuer == "CN=MyCA, OU=MyUnit, O=MyOrg, C=DE"
};

/////////////////////////////////////////
// Technical system based on JWT
permit (
	principal == Subject::"TechSys02",
	action in [Action::"GET", Action::"POST", Action::"DELETE"],
	resource is Route
) when {
	context.type == "jwt"
	&& context.route like "myorg.com/api/*"
	&& context.issuer == "https://iam.myorg.com/"
};

/////////////////////////////////////////
// Users based on JWT accessing the CMK Backend via the CMK UI
permit (
	principal is Subject,
	action in [Action::"GET", Action::"POST"],
	resource is Route
) when {
	context.type == "jwt"
	&& context.route like "myorg.com/cmk/*"
	&& context.issuer == "https://iam.myorg.com/"
};
