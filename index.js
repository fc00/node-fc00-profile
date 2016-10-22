var Basic = require("./basic.json");
var Crypto = require("crypto");
var CjdnsKeys = require("cjdnskeys");

var Profile = module.exports;

var randomBytes = Profile.randomBytes = function (l) {
    var s = '';
    while (s.length < l) {
        s += Crypto.randomBytes(l).toString('base64');
        s = s.replace(/[+\/]+/g, '').slice(0, l);
    }
    return s;
};

var randomPort = Profile.randomPort = function () {
    return 1000 + Math.floor(Math.random() * 64535);
};

var clone = function (o) { return JSON.parse(JSON.stringify(o)); };

var copyStructure = function (A, B) {
    // very primitive and not entirely safe. YMMV
    Object.keys(B).forEach(function (k) {
        A[k] = A[k] || clone(B[k]);
    });
};

var isValidFc = function (ip6) {
    return typeof(ip6) === 'string' &&
        ip6.length === 39 &&
        /^fc/.test(ip);
};

Profile.create = function (profile) {
    profile = profile || {};

    copyStructure(profile, Basic);

    profile.setKeys = function (priv) {
        var tmp = { };

        try {
            if (typeof(priv) === 'string' && priv.length === 64) {
                tmp.privateKey = priv;
                pub = CjdnsKeys.privateToPublic(priv);
                ip6 = CjdnsKeys.publicToIp6(pub);
            }
        } catch (err) {}

        if (!isValidFc(tmp.ip6)) { tmp = CjdnsKeys.keyPair(); }

        Object.keys(tmp).forEach(function (k) {
            profile[k] = tmp[k];
        });
    };

    profile.addPassword = function (len, user) {
        var passwd = { password: randomBytes(len || 32) };
        if (typeof(user) === 'string') { passwd.user = user; }
        profile.authorizedPasswords.push(passwd);
        return clone(passwd);
    };


    profile.bindUDP = function (port, address, type) {
        var UDP = profile.interfaces.UDPInterface;
        port = port || randomPort();

        var bound = function (s) {
            return UDP.some(function (iface) {
                return iface.bind === s;
            });
        };

        var bind = function (s) {
            UDP.push({
                bind: s,
                connectTo: {},
            })
        };

        var tmp;


        switch (type) {
            case 4:
            case '4':
                tmp = (address || '0.0.0.0') + ':' + port;
                break;

                // FALLTHROUGH
            case 6:
            case '6':
            default:
                tmp = (address || '[::]') + ':' + port;
                if (!bound(tmp)) { bind(tmp); }
                break;
        }
    };

    profile.bindETH = function (beacon, bind) {
        var ETH = profile.interfaces.ETHInterface;
        bind = bind || 'all';
        beacon = typeof(beacon) === 'number'?beacon: 2;

        var I;
        if (ETH && ETH.length && ETH.some(function (iface, i) {
            I = i;
            return iface && iface.bind === bind;
        })) {
            if (typeof(ETH[I]) === 'object' && ETH[I].beacon !== beacon) { ETH[I].beacon = beacon; }
            return;
        }
        ETH.push({
            bind: bind,
            beacon: beacon,
            connectTo: {}
        });
    };

    profile.bindAdmin = function (password, port, address) {
        var admin = profile.admin;
        admin.bind = (address || '127.0.0.1') + ':' + (port || 11234);
        admin.password = password || 'NONE';
    };

    profile.addOutgoingTunnel = function (opt) {
        console.error("Profile.addOutgoingTunnel is not implemented yet!");
        return false;
    };

    profile.addAllowedConnection = function (opt) {
        console.error("Profile.addAllowedConnection is not implemented yet!");
        return false;
    };

    profile.setSaneDefaults = function () {
        // TODO find a UDP port that isn't already bound
        var UDPPort = randomPort();

        profile.setKeys(profile.privateKey);

        profile.bindUDP(UDPPort);
        profile.bindAdmin();
        profile.bindETH(2, 'all');
    };

    return profile;
};


