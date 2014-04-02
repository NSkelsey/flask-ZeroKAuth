function _hash(){
    /* this function accepts a variable number of args and
    returns a bigint representation of the SHA256 of those inputs.
    bigInts and numbers are converted to hex before hashing */
    var args = Array.prototype.slice.call(arguments);
    function upd(accumulator, element){
        var hex_element = null;

        if(typeof(element) === "object" && element.constructor == BigInteger){
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
        request.send(d_as_json)
    };
}
