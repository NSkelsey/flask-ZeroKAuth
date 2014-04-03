function _hash(){
    /* this function accepts a variable number of args and
    returns a bigint representation of the SHA256 of those inputs.
    bigInts and numbers are converted to hex before hashing */
    var args = Array.prototype.slice.call(arguments);
    function upd(accumulator, element){
        var hex_element = null;

        if(typeof(element) === "object" && element.constructor === BigInteger){
            // console.log("bigint");
            hex_element = element.toString(16);
        }
        else if(typeof(element) === "number"){
            // console.log("num");
            hex_element = element.toString(16);
        }
        else if(typeof(element) === "string"){
            // console.log("str");
            hex_element = element;
        }
        else{
            throw "_hash element type not valid";
        }
        return accumulator + hex_element;
    }
    var hashp = args.reduce(upd, "");
    //       console.log("=================");
    //       console.log(hashp);
    //       console.log("=================");
    var hashVal = CryptoJS.SHA256(hashp).toString();
    var bigResult = new BigInteger(hashVal, 16);
    return bigResult;
}

function groupConstants(){
    var constants = {
        g_decstring: '2',
        N_hexstring: 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3'
    };
    return constants;

    // var g_decstring = '2';
    // var N_hexstring = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3';
    // g = new BigInteger(g_decstring, 10);
    // N = new BigInteger(g_hexstring, 16);
    // return [g_decstring, N_hexstring];
    // return[g, N];
}

function createAccount(username, password){
    var constants = groupConstants();
    var g = new BigInteger(constants.g_decstring, 10);
    var N = new BigInteger(constants.N_hexstring, 16);
    var k = _hash(N, g);

    var salt = CryptoJS.lib.WordArray.random(64/8).toString();
    var x = _hash(salt, ":", password);
    var v = g.modPow(x, N)
    console.log("I: ", username);
    console.log("s: ", salt);
    console.log("v: ", v.toString(16));

    var payload = { // s is a hex str
                   's': salt,
                   // v is a hex str
                   'v': v.toString(16),
                   'username' : username
                   };
    var d_as_json = JSON.stringify(payload);
    console.log(d_as_json);

    var request = new XMLHttpRequest();
    request.open('POST', '/create', true);
    request.setRequestHeader('Content-Type', 'application/json');
    request.send(d_as_json);
}

function handshake(username, password){
    //get groupConstants, g and N, and represent them using BigIntegers
    // var constants_array = groupConstants();
    // var g = new BigInteger(constants_array[0], 10);
    // var N = new BigInteger(constants_array[1], 16);
    var constants = groupConstants();
    var g = new BigInteger(constants.g_decstring, 10);
    var N = new BigInteger(constants.N_hexstring, 16);

    //generate random a; use to find A = g^x
    var a_hex = CryptoJS.lib.WordArray.random(512/8).toString();
    var a = new BigInteger(a_hex, 16);
    var A = g.modPow(a, N)


    // var a = generate_a_A.a;
    // var A = generate_a_A.A;
    // function generate_a_A(N){
    //     var a_hex = CryptoJS.lib.WordArray.random(512/8).toString();
    //     var results = {
    //         var a = new BigInteger(a_hex, 16);
    //         var A = g.modPow(a, N)
    //     };
    //     return results;
    // }

    console.log("a: ", a.toString(16));
    console.log("A: ", A.toString(16));

    //construct JSON with username and A
    var payload = {'username': username,
                   'A': A.toString(16)
                   };
    var d_as_json = JSON.stringify(payload);
    console.log(d_as_json);

    var request = new XMLHttpRequest();
    request.onload = reqListener;
    // timeout on request does not work------------
    request.timeout = 1000;
    request.ontimeout = function () { console.log("TIMEOUT TIMEOUT YOU ARE IN TIMEOUT"); }
    //---------------------------------------------
    request.open('POST', '/handshake', true);
    request.setRequestHeader('Content-Type', 'application/json');
    request.send(d_as_json);

    //listens to reponse from request; this JSON repsonse containts (salt, B)
    function reqListener () {
        console.log(this.responseText);
        sAndB = JSON.parse(this.responseText);
        console.log('sAndB, s:', sAndB.s);
        console.log('sAndB, B:', sAndB.B);
        verify(username, password, g, N, A, a, sAndB.s, sAndB.B);
    }

    /**    
    the idea for handling timeouts [TODO, currently only handles success]:
    ['succes' = valid and existent response from request]
    -- have both listener and timeout happening concurrently.
    -- if server responds with JSON{s, B}; great! timeout does not 
       hit and reqListener does, proceed to verify.
    -- if server does not respond reqListener never hits but then
       timeout function does! execute and abort. ensure reqListener
       doesn't also hit if somehow JSON{s, B} does/can make it through.
            -- call abort on request before calling JS abort function
    **/
}


function verify(username, password, g, N, A, a, s, B){
    // refrences to handshake's g, N, and A save time/space
    // var constants_array = groupConstants();
    // var g = new BigInteger(constants_array[0], 10);
    // var N = new BigInteger(constants_array[1], 16);
    // var A = g.modPow(a, N);
    var B = new BigInteger(B, 16);
    var s = new BigInteger(s, 16)
    var k = _hash(N, g);
    var u = _hash(A, B);

    console.log('Verify Initial Constants----------------------------------------');
    console.log('username | ', username);
    console.log('password | ', password);
    console.log('g        | ', g.toString());
    console.log('N        | ', N.toString());
    console.log('A        | ', A.toString());
    console.log('a        | ', a.toString());
    console.log('s        | ', s.toString());
    console.log('B        | ', B.toString());
    console.log('k        | ', k.toString());
    console.log('u        | ', u.toString());

    //odd the hardness of the entire scheme relies upon these two if statements
    //i presume the entire scheme relies upon every statement
    if(u === 0){
        abort('u = _hash(a, b) equated zero');
    }
    if(B.remainder(N) === 0){
        abort('B mod N equated zero');
    }

    //produce and hash the secret
    var x = _hash(s, ':', password);
    var aPLUSux = a.add( u.multiply(x) );
    var BMINUSkgTOx = B.subtract( k.multiply( g.modPow(x, N) ) );
    var S_c = BMINUSkgTOx.modPow(aPLUSux, N)
    var K_c = _hash(S_c);

    //produce and hash M1 #moonmath
    var HNxorHg = _hash(N).xor(_hash(g));
    var M1 = _hash(HNxorHg, _hash(username), s, A, B, K_c);

    //construct JSON with M1
    var payload = {'username': username,
                    'M1': M1.toString(16)
                    };
    var d_as_json = JSON.stringify(payload);

    //TODO: reference to handshake's request could also be passed in?
    var request = new XMLHttpRequest();
    request.onload = reqListener;
    // timeout on request does not work------------
    request.timeout = 2000;
    request.ontimeout = function () { console.log("TIMEOUT TIMEOUT YOU ARE IN TIMEOUT"); }
    //---------------------------------------------
    request.open('POST', '/verify', true);
    request.setRequestHeader('Content-Type', 'application/json');
    request.send(d_as_json);

    //listens to reponse from request; this JSON repsonse containts (salt, B)
    function reqListener () {
        console.log(this.responseText);
        M2 = JSON.parse(this.responseText);
    }
    


    console.log('Verify Computations---------------------------------------------');
    console.log('x           | ', x.toString());
    console.log('aPLUSux     | ', aPLUSux.toString());
    console.log('BMINUSkgTOx | ', BMINUSkgTOx.toString());
    console.log('S_c         | ', S_c.toString());
    console.log('K_c         | ', K_c.toString());
    console.log('HNxorHg     | ', HNxorHg.toString());
    console.log('M1          | ', M1.toString());
    console.log('json        | ', d_as_json);


}

function abort(errorMessage){
    //we want a better abort handler than this
    //we won't to actually throw an error, just fail elegantly
    console.log("ERROR: ", errorMessage);
    throw { name: 'FatalError', message: errorMessage };
}











// ------------^^^new code^^^----------\/ \/old code\/ \/---------


function Client() {
    g = "2"
    hexString_N = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3';
    this.N = new BigInteger(hexString_N, 16);
    this.g = new BigInteger(g, 10);
    this.k = _hash(this.N, this.g);
    this.createAccount = function(username, password) {
        // Salt is a random hex string
        var salt = CryptoJS.lib.WordArray.random(64/8).toString();
        var x = _hash(salt, ":", password);
        this.v = this.g.modPow(x, this.N)
        console.log("I: ", username);
        console.log("s: ", salt);
        console.log("v: ", this.v.toString(16));

        var payload = { // s is a hex str
                       's': salt,
                       // v is a hex str
                       'v': this.v.toString(16),
                       'username' : username
                       };
        var d_as_json = JSON.stringify(payload);
        console.log(d_as_json);

        var request = new XMLHttpRequest();
        request.open('POST', '/create', true);
        request.setRequestHeader('Content-Type', 'application/json');
        request.send(d_as_json);
    };
    this.authenticate = function(username){};
        this.handshake = function(username){
            var a_hex = CryptoJS.lib.WordArray.random(512/8).toString();
            //having both upper and lower case is not 
            var a = new BigInteger(a_hex, 16);
            var A = new BigInteger(g.toString(10), 10);
            A = A.modPow(a, N);

            console.log("a: ", this.a.toString(16));
            console.log("A: ", this.A.toString(16));

            var payload = {'username': username,
                           // v is a hex str
                           'A': this.A.toString(16)
                           };
            var d_as_json = JSON.stringify(payload);
            console.log(d_as_json);

            var request = new XMLHttpRequest();
            request.onload = reqListener;
            request.open('POST', '/handshake', true);
            request.setRequestHeader('Content-Type', 'application/json');
            request.send(d_as_json);

            function reqListener () {
                console.log(this.responseText);
                console.log('test: ', a.toString());
                console.log('v from: ', v.toString());
                JSON.parse(string);
            }

        };
}
