// opcuaSecurity.js
async function queryAnonymousEndpoints(client, endpointUrl, opcuaLib, withTimeoutFn) {
  const result = {
    endpointsQueried: false,
    advertisedAnonymous: false,
    anonymousEndpoints: []
  };
  try {
    const endpoints = await withTimeoutFn(client.getEndpoints({ endpointUrl }), 6000, 'Timeout getting endpoints');
    result.endpointsQueried = Array.isArray(endpoints) && endpoints.length > 0;
    if (Array.isArray(endpoints)) {
      const anonEndpoints = [];
      for (const ed of endpoints) {
        const tokens = Array.isArray(ed.userIdentityTokens) ? ed.userIdentityTokens : [];
        const hasAnon = tokens.some(t => t.tokenType === opcuaLib.UserTokenType.Anonymous);
        if (hasAnon) {
          anonEndpoints.push({
            endpointUrl: ed.endpointUrl || endpointUrl,
            securityMode: String(ed.securityMode),
            securityPolicyUri: ed.securityPolicyUri
          });
        }
      }
      result.advertisedAnonymous = anonEndpoints.length > 0;
      result.anonymousEndpoints = anonEndpoints;
    }
  } catch {
    result.endpointsQueried = false;
  }
  return result;
}

module.exports = { queryAnonymousEndpoints };


