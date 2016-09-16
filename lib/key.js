import {configure, getPEM} from 'pan-domain-public-keys';

export default function(domain, refresh, overrideHttps) {
    // Use the internal cache to avoid multiple requests, but expire the
    // key after 'refresh' milliseconds
    configure({
        expires: refresh
    });

    return function() {
        return getPEM(domain, overrideHttps);
    };
}
