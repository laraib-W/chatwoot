import Auth from '../auth';
import { clearCookiesOnLogout } from '../../store/utils/api';

vi.mock('../../store/utils/api', () => ({
  clearCookiesOnLogout: vi.fn(),
  deleteIndexedDBOnLogout: vi.fn(),
}));

// logout-flow: per-app logout under SSO is navigation-only, to the portal.
describe('Auth.logout', () => {
  beforeEach(() => {
    window.axios = { delete: vi.fn(() => Promise.resolve({})) };
  });
  afterEach(() => {
    window.globalConfig = undefined;
    vi.clearAllMocks();
  });

  it('makes no sign-out call under SSO and navigates to the portal', async () => {
    window.globalConfig = {
      AUTH_TYPE: 'SSO',
      MPASS_PORTAL_URL: 'https://foss.local.dev',
    };
    await Auth.logout();
    expect(window.axios.delete).not.toHaveBeenCalled();
    expect(clearCookiesOnLogout).toHaveBeenCalledWith('https://foss.local.dev');
  });

  it('keeps the stock sign-out call without SSO', async () => {
    window.globalConfig = { AUTH_TYPE: '' };
    await Auth.logout();
    expect(window.axios.delete).toHaveBeenCalled();
  });
});
