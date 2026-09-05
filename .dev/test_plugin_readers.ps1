Add-Type -AssemblyName System.Windows.Forms
$form = New-Object System.Windows.Forms.Form
$browser = New-Object System.Windows.Forms.WebBrowser
$form.Controls.Add($browser)
$html = @"
<!DOCTYPE html>
<html>
<body>
    <object id="plugin" classid="clsid:078EF12E-A5ED-5374-9D3A-DBC93D57750E"></object>
    <div id="res"></div>
    <script>
        setTimeout(function() {
            var p = document.getElementById("plugin");
            if (!p || !p.readers) { document.getElementById("res").innerText = "NO_PLUGIN"; return; }
            var out = [];
            for (var i = 0; i < p.readers.length; i++) {
                var r = p.readers[i];
                var name = "";
                try { name = r.name; } catch(e) { name = "err_name"; }
                var conn = "NON";
                try {
                    r.connect(2);
                    conn = "OUI_CONNECTE";
                    r.disconnect();
                } catch(ec) {
                    conn = "ECHEC: " + ec.message;
                }
                out.push(i + ": " + name + " -> " + conn);
            }
            document.getElementById("res").innerText = out.join("\n");
        }, 300);
    </script>
</body>
</html>
"@
$browser.DocumentText = $html
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$count = 0
$timer.Add_Tick({
    $count++
    $elem = $browser.Document.GetElementById("res")
    if ($elem -and $elem.InnerText -ne "" -or $count -gt 20) {
        $timer.Stop()
        Write-Host $elem.InnerText
        $form.Close()
    }
})
$timer.Start()
[System.Windows.Forms.Application]::Run($form)
