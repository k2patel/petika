import init, {
  Session,
  generate
} from './wasm/petika_web.js';
import {
  parseOtp,
  totp
} from './otp.js';
let session;
const ready = init();
let queue = Promise.resolve();
self.onmessage = ({
  data
}) => {
  queue = queue.then(async () => {
    const {
      id,
      action,
      args = []
    } = data;
    try {
      await ready;
      let value;
      switch (action) {
        case 'create':
          session?.free();
          session = Session.create(...args);
          break;
        case 'open': {
          const opened = Session.open(new TextEncoder().encode(args[0]), args[1]);
          session?.free();
          session = opened;
          break;
        }
        case 'list':
          value = JSON.parse(session.list());
          break;
        case 'get': {
          value = JSON.parse(session.get(args[0]));
          value.otp = Boolean(value.otp);
          break;
        }
        case 'edit':
          value = JSON.parse(session.get(args[0]));
          break;
        case 'put':
          parseOtp(args[1].otp || '');
          session.put(args[0], JSON.stringify(args[1]), args[2]);
          break;
        case 'remove':
          session.remove(args[0]);
          break;
        case 'seal':
          value = new TextDecoder().decode(session.seal());
          break;
        case 'mode':
          value = session.mode();
          break;
        case 'generate':
          value = generate(args[0]);
          break;
        case 'otp':
          value = await totp(JSON.parse(session.get(args[0])).otp || '');
          break;
        case 'rewrap':
          session.change_passphrase(args[0]);
          break;
        default:
          throw new Error('Unknown operation');
      }
      self.postMessage({
        id,
        value
      });
    } catch (error) {
      self.postMessage({
        id,
        error: String(error.message || error)
      });
    }
  });
};
