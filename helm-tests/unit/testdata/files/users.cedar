// Users of the CMK UI: browser sessions through Session Manager, on tenant paths.
permit (
  principal is Subject,
  action in [
    Action::"GET", Action::"POST", Action::"PUT", Action::"PATCH", Action::"DELETE"
  ],
  resource
) when {
  context.type == "session" &&
  context.path like "/cmk/v1/*"
};
