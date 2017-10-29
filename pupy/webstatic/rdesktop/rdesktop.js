var RDHANDLER = function (port) {
    var self = this;
    RDHANDLER.prototype.print=(function (msg){
            $('#messages').append(msg+'<br />');
    });
    RDHANDLER.prototype.start=(function (){
        if ("WebSocket" in window) {
            var url="ws://"+window.location.hostname+":"+port+"/"+window.location.pathname.split("/",2)[1]+"/ws";
            self.print(url);
            self.ws = new WebSocket(url);
            self.ws.onopen = function() {
                self.print("Websocket connected !");
                self.start_stream();
            };
            self.ws.onmessage = function (evt) { 
                var data = jQuery.parseJSON(evt.data);
                if('message' in data) {
                    self.print(data.message);
                }
                else if('screen' in data) {
                    //$('#screen').attr('style', "background-image:url(data:image/gif;base64,"+data['screen']+");width:"+data['width']+"px;height:"+data['height']+"px;")
                    $('#screenimg').attr('src', "data:image/jpg;base64,"+data['screen']);
                    //;width:"+data['width']+"px;height:"+data['height']+"px;")
                }
            };
            self.ws.onclose = function() { 
                self.print("Connection is closed...");
            };
        } else {
            self.print("WebSocket NOT supported by your Browser!");
        }
    });
    RDHANDLER.prototype.start_stream=(function (){
        self.ws.send("start_stream");
    });
    self.start();
}
