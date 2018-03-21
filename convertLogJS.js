#!/usr/bin/env node

SEPARATOR = /^--([0-9a-f]+)-([A-Z])--$/;

class RequestHeader {
	constructor() {
		this.headers = {};
		this.method = undefined;
		this.path = undefined;
		this.version = undefined;
	}
	
	//override append-concat
	attach(line) {
		if (!line.trim()) {
			return;
		}
    		if (this.method !== undefined) {
			var tmpSplit = line.split(/:(.+)/); //split ":" in an array of 2, leaving the second part unscathed
      		this.headers[tmpSplit[0]] = tmpSplit[1];
		}
    		else{
			var tmpSplitted = line.split(" ");
			this.method = tmpSplitted[0];
			this.path = tmpSplitted[1];
			this.version = tmpSplitted[2];
		}
	}
}


class RequestBody {
	constructor() {
		this.data = undefined;
	}
	
	//override append-concat
	attach(line) {
		if (!line.trim()) {
			return;
		}
	    this.data = line;
	}
}

class ResponseHeader {
	constructor() {
		this.headers = {};
		this.status = undefined;
		this.version = undefined;
		this.reason = undefined;
	}
	
	//override append-concat
	attach(line) {
		if (!line.trim()) {
			return;
		}
		if (this.status !== undefined) {
			var tmpSplit = line.split(/:(.+)/); //split ":" in an array of 2, leaving the second part unscathed
      		this.headers[tmpSplit[0]] = tmpSplit[1];
		} else {
			var tmpSplitted = line.split(" ");
			this.version = tmpSplitted[0];
			this.status = tmpSplitted[1];
			this.reason = tmpSplitted[2];
		}
	}
}

class Message {
	constructor(line) {
		this.data = {};
		this.parse(line);
	}

	parse(line) {
		var arrayMatch = line.match(/(.+?) (\[.+\])/); //separate message (index 1) from other fields(index 2)
		var message;
        var data;
		if(arrayMatch) {
			data = arrayMatch[arrayMatch.length-1];
			message = arrayMatch[arrayMatch.length-2];
			this.data = this.parse_data(data);
		} else {
			message = line;
		}
		if(this.data['msg'] === undefined) {
			this.data['msg'] = "";
		}
		this.data['message'] = message.trim();
	}

	parse_data(line) {
		var data = {};
		//npm install StringScanner
		var StringScanner = require("StringScanner");
		var ss = new StringScanner(line);
		ss.scan(/\s*/);

		while(!ss.eos()) {
            ss.scan(/\[/);
			var key = ss.scan(/.+? /).trim();
			var value = "";
            ss.scan(/"/);

			do {
				if(ss.scan(/\\./)) {
					value += ss.match();
				} else if (ss.scan(/[^\\"]+/)) {
					value += ss.match();
				} else {
					value += "";
				}
			}
			while(!((ss.scan(/"/)) || (ss.eos())));

			ss.scan(/\]\s*/);
			data[key] = value;
		}
		return data;
	}
}

class AuditLogTrailer {
	constructor() {
		this.metadata = {'Messages':[]};
	}

	attach(line) {
		if (!line.trim()) {
			return;
		}
        var matchMsg = (line.match(/^Message: (.+)/));
		if (matchMsg) {
			this.metadata['Messages'].push(new Message(matchMsg[matchMsg.length-1]));
		} else {
			var tmpSplit = line.split(/:(.+)/); //split ":" in an array of 2, leaving the second part unscathed
      		this.metadata[tmpSplit[0]] = tmpSplit[1];
		}
	}
}


//MAIN
var transaction = undefined;
var section = undefined;
//reading input file
var fs = require('fs'),
  readline = require('readline'),
   instream = fs.createReadStream('./modsec_audit.log.1'),
    outstream = new (require('stream'))(),
     rl = readline.createInterface(instream, outstream);
     
rl.on('line', function (line) {
  line = line.trim();
  var fsWrite = require('fs');
  if(line.match(SEPARATOR)) {
	var section_id = line.match(SEPARATOR)[2];
	switch(section_id) {
		case 'A':
			transaction =  {}; //hashmap
			section = undefined;
			break;
        case 'B':
			section = new RequestHeader();
			transaction['RequestHeader'] = section;
			break;
		case 'C':
			section = new RequestBody();
			transaction['RequestBody'] = section;
			break;
		case 'E':
			section = "";
			transaction['IntendedResponseBody'] = section;
			break;
		case 'F':
			section = new ResponseHeader();
			transaction['ResponseHeader'] = section;
			break;
		case 'H':
			section = new AuditLogTrailer();
			transaction['AuditLogTrailer'] = section;
			break;
		case 'Z':
        //    fsWrite.open('/tmp/convertLog.txt', 'a', (err, fd) => {
         //       if (err) throw err;
          //      fsWrite.appendFile(fd, JSON.stringify(transaction)+"\r\n", 'utf8', (err) => {
           //         fsWrite.close(fd, (err) => {
            //            if (err) throw err;
            //        });
             //       if (err) throw err;
           //     });
       //     });
			console.log(JSON.stringify(transaction));
			section = undefined;
			transaction = undefined;
			break;
		default:
			section = "";
			transaction[section_id] = section
	}
   } else {
	if(section !== undefined) {
		if((section instanceof RequestHeader) || section instanceof RequestBody || (section instanceof ResponseHeader) || (section instanceof AuditLogTrailer)) {
			section.attach(line);
		} else {
			section = section + line; //it is a string for example
		}
	} else {
        //A and Z section (first and last for each block)
		section = line;
	}
   }
});
    
rl.on('close', function (line) {
});
