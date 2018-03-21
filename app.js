var ModSecLog2JSON = require('./ModSecLog2JSON.js')


var log2json = new ModSecLog2JSON()

log2json.async("/tmp/modsec_audit.log.1",
function callback(jsonArray){
        //console.log(JSON.stringify(jsonArray[0]))
        /*
        for(i=0;i<1000;i++){
            console.log(jsonArray[i].AuditLogTrailer.metadata.Messages[0])
            console.log("##############################################################################################")
        }
        */
        
})
