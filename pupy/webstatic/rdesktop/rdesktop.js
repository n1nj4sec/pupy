var RDHANDLER = function (port) {
    var self = this;
    var last_move = null;

    RDHANDLER.prototype.print=(function (msg) {
            $('#messages').append(msg+'<br />');
    });

    RDHANDLER.prototype.start=(function () {
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
                if('message' in data) {
                    self.print(data.message);
                }
                else if('screen' in data) {
                    $('#screenimg').attr('src', "data:image/jpg;base64,"+data['screen']);
                }
            };

            self.ws.onclose = function() {
                self.print('Connection is closed... reconnecting ...');
                self.start();
            };
        } else {
            self.print("WebSocket NOT supported by your Browser!");
        }
    });

    RDHANDLER.prototype.start_stream=(function () {
        self.ws.send(JSON.stringify({"msg": "start_stream"}));
    });

    RDHANDLER.prototype.on_key_press=(function (e) {
        self.ws.send(JSON.stringify({"msg": "keypress", "key": e.key}));
    });

    RDHANDLER.prototype.on_click=(function (e) {
        pos_x = e.pageX-document.getElementById("screen").offsetLeft;
        pos_y = e.pageY-document.getElementById("screen").offsetTop;
        self.ws.send(JSON.stringify({"msg":"click", "x":pos_x, "y": pos_y}));
    });

    RDHANDLER.prototype.on_mouse_move=(function (e) {
        if (last_move==null || (Date.now()-self.last_move > 10)) {
            self.last_move = Date.now();
            pos_x = e.pageX-document.getElementById("screen").offsetLeft;
            pos_y = e.pageY-document.getElementById("screen").offsetTop;
            self.ws.send(JSON.stringify({"msg":"move", "x":pos_x, "y": pos_y}));
        }
    });
}
