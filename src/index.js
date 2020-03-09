const axios = require('axios').default;
const parser = require('xml2js');

async function authPlugin(logger, config) {
  return {
    authenticate: async function(req) {
      logger.info('Authenticating request for session:', req.session.id);

      if (!req.session.service) {
        req.session.service = _constructPageUrl(req);
        await saveSession(req);
      }
      const ticket = req.query.ticket;

      if (!ticket) {
        return { type: 'redirect', url: `${config.server}/login?service=${req.session.service}` };
      } else {
        logger.info('Got CAS ticket. Requesting validation.');
        const response = await axios.get(`${config.server}/serviceValidate`, {
          params: {
            ticket: req.query.ticket,
            service: req.session.service
          }
        });

        const xml = await parser.parseStringPromise(response.data);

        if (!xml['cas:serviceResponse'] || !xml['cas:serviceResponse']['cas:authenticationSuccess']) {
          logger.warn('Authentication failed');
          return { type: 'unauthorized' };
        }

        logger.info('Request validated.');
        const uid = xml['cas:serviceResponse']['cas:authenticationSuccess'][0]['cas:user'][0];

        if (uid) {
          delete req.session.service;
          await saveSession(req);
          return { type: 'success', uid };
        } else {
          return { type: 'unauthorized' };
        }
      }
    }
  };
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(function(err) {
      if (err) return reject(err);
      resolve();
    });
  });
}

function _constructPageUrl(req) {
  const protocol = req.secure ? 'https' : 'http';
  const hostname = req.headers.host;

  return `${protocol}://${hostname}${req.originalUrl}`;
}

module.exports = authPlugin;
