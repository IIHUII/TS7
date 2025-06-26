 // ========================================
        // FILES CONFIGURATION
        // ========================================
        const FILES_DATA = [
            {
                id: "Dark hub 1",
                name: "Dark Hub 1",
                type: "txt",
                size: "73KB",
                description: "سكربت سجاد بحث : deep or drak hub",
                downloads: "8",
                category: "سجاد",
                content: `local args = {
    [1] = "RolePlayName",
    [2] = "مًطِوٌر آلَسِکْربًتٌ سِجّآدٍ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))

local args = {
    [1] = "RolePlayBio",
    [2] = ""
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))

local player = game.Players.LocalPlayer
local gui = Instance.new("ScreenGui", player:WaitForChild("PlayerGui"))
gui.Name = "DeltaWelcome"
gui.ResetOnSpawn = false

local main = Instance.new("Frame")
main.Parent = gui
main.AnchorPoint = Vector2.new(0.5, 0.5)
main.Position = UDim2.new(0.5, 0, 0.4, 0)
main.Size = UDim2.new(0, 450, 0, 150)
main.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
main.BackgroundTransparency = 0.2
main.BorderSizePixel = 0
main.Visible = false

local corner = Instance.new("UICorner", main)
corner.CornerRadius = UDim.new(0, 20)

-- الأيقونة على اليسار
local icon = Instance.new("ImageLabel", main)
icon.Size = UDim2.new(0, 60, 0, 60)
icon.Position = UDim2.new(0, 10, 0, 10)
icon.BackgroundTransparency = 1
icon.Image = "rbxassetid://131337234636792" -- غيّر الـID حسب رغبتك

-- النص
local text = Instance.new("TextLabel", main)
text.Size = UDim2.new(1, -80, 1, -20)
text.Position = UDim2.new(0, 80, 0, 10)
text.BackgroundTransparency = 1
text.Text = "مطور سكربت سجاد!"
text.TextColor3 = Color3.new(1, 1, 1)
text.Font = Enum.Font.GothamBold
text.TextScaled = true
text.TextWrapped = true
text.TextXAlignment = Enum.TextXAlignment.Left
text.TextYAlignment = Enum.TextYAlignment.Center

-- أنميشن الدخول
main.Visible = true
main.BackgroundTransparency = 1
text.TextTransparency = 1
icon.ImageTransparency = 1

for i = 1, 10 do
	main.BackgroundTransparency -= 0.08
	text.TextTransparency -= 0.1
	icon.ImageTransparency -= 0.1
	wait(0.03)
end

wait(5) -- كم ثانية تبقى

-- أنميشن الخروج
for i = 1, 10 do
	main.BackgroundTransparency += 0.08
	text.TextTransparency += 0.1
	icon.ImageTransparency += 0.1
	wait(0.03)
end

gui:Destroy()
wait(0.1)
game.StarterGui:SetCore("SendNotification", {
    Title = " جاري تشغيل";
    Text = "جاري تشغيل"; -- ARAB TEAM
    Duration = 5;
})
wait(0.1)
game.StarterGui:SetCore("SendNotification", {
    Title = " المطور سجاد";
    Text = "المطور سجاد"; -- ARAB TEAM
    Duration = 5;
})

loadstring(game:HttpGet(("https://raw.githubusercontent.com/Sadfffaj/-/refs/heads/main/%D8%AC%D8%A7%D8%B1%D9%8A%20%D8%AA%D8%B9%D9%84%D9%85%20%D8%A7%D9%84%D9%87.txt")))()
MakeWindow({
  Hub = {
    Title = "DARK HUH",
    Animation = "DARK HUH"
  },
    Key = {
    KeySystem = true,
    Title = "Key System",
    Description = "تلكه المفتاح بقناتي تلي ",
    KeyLink = "https://t.me/xxx90xxxiii",
    Keys = {"SAD55"},
    Notifi = {
      Notifications = true,
      CorrectKey = "المفتاح صحيح",
      Incorrectkey = "المفتاح خطأ",
      CopyKeyLink = "تم النسخ في الحافظة"
    }
  }
})
MinimizeButton({
  Image = "rbxassetid://98360849741395",
  Size = {50, 50},
  Color = Color3.fromRGB(255, 125, 0),
  Corner = true,
  Stroke = false,
  StrokeColor = Color3.fromRGB(255, 125, 0)
})

local Main = MakeTab({Name = "معلومات"})
AddDiscord(Main, {
    DiscordLink = "https://t.me/xxx90xxxiii",
    DiscordIcon = "rbxassetid://98360849741395",
    DiscordTitle = "انضم لقناتي لتعرف كلشي جديد",
    })
AddDiscord(Main, {
    DiscordLink = "https://t.me/xxx22zx",
    DiscordIcon = "rbxassetid://98360849741395",
    DiscordTitle = "كروبنا",
    })
AddButton(Main, {
  Name = "نسخ حسابي روبلوكس",
  Callback = function()
    setclipboard('SAGAD455')
  end
})
AddButton(Main, {
  Name = "نسخ حسابي تيك توك",
  Callback = function()
    setclipboard('8.9v3')
  end
})

local Main = MakeTab({Name = "كلشي وكلاشي"})

AddButton(Main, {
  Name = "رجل مقطوعه ",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رجل حديدة",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 17500249989,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس مخفي",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "راس روبوت",
  Callback = function()
    local args = {
    [1] = 3210773801
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس روكر",
  Callback = function()
    local args = {
    [1] = 134082579
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس كيوت",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 746767604
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
  local args = {
    [1] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

wait(0.1)
end
})
  AddButton(Main, {
  Name = " القزم",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = {
        [1] = 14579958702,
        [2] = 14579959062,
        [3] = 14579959191,
        [4] = 14579959249,
        [5] = 14579963667,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

wait(0.1)
  end
})
AddButton(Main, {
  Name = "قزومي",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 18599265011,
        [2] = 18599265151,
        [3] = 18599265190,
        [4] = 18599265270,
        [5] = 18599264796,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "عيون حادة",
  Callback = function()
  local args = {
    [1] = 16580493236
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

   end
})
AddButton(Main, {
  Name = "رجل العظام الرصاصي",
  Callback = function()
    print("Clicked")local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 17500249989,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "رجل العظام السود",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 14547162578,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "رجل رول",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 3230472745,
        [5] = 3230470862,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جسم بنت ضعيف خصر",
  Callback = function()
local args = {
    [1] = {
        [1] = 74302534603111,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})


AddButton(Main, {
  Name = "بنية جسم",
  Callback = function()
local args = {
    [1] = {
        [1] = 96491916349570,
        [2] = 14854350570,
        [3] = 14854350451,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "بنت جسم",
  Callback = function()
local args = {
    [1] = {
        [1] = 16214246112,
        [2] = 16214249513,
        [3] = 16214251181,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
local args = {
    [1] = {
        [1] = 15539008532,
        [2] = 15539008875,
        [3] = 15539008680,
        [4] = 15539008795,
        [5] = 15539011945,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
local args = {
    [1] = {
        [1] = 14861800638,
        [2] = 14861800626,
        [3] = 14861801452,
        [4] = 14861800627,
        [5] = 14861801454,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم ولد",
  Callback = function()
local args = {
    [1] = {
        [1] = 17754346388,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم ولد ضعيفم",
  Callback = function()
local args = {
    [1] = {
        [1] = 92757812011061,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})


AddButton(Main, {
  Name = "جسم ولد كوبي",
  Callback = function()
local args = {
    [1] = {
        [1] = 86499666,
        [2] = 27112039,
        [3] = 27112052,
        [4] = 27112068,
        [5] = 27112056,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جسم ولد رول",
  Callback = function()
local args = {
    [1] = {
        [1] = 27112025,
        [2] = 27112039,
        [3] = 27112052,
        [4] = 3230472745,
        [5] = 3230470862,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "سيغما بوي",
  Callback = function()
local args = {
    [1] = {
        [1] = 18178775358,
        [2] = 18178775182,
        [3] = 18178775725,
        [4] = 18178777453,
        [5] = 18178775695,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

end})

AddButton(Main, {
  Name = "جسم قزم ",
  Callback = function()
local args = {
    [1] = {
        [1] = 14579958702,
        [2] = 14579959062,
        [3] = 14579959191,
        [4] = 14579959249,
        [5] = 14579963667,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم قزم2",
  Callback = function()
local args = {
    [1] = {
        [1] = 77813057823038,
        [2] = 135110043370135,
        [3] = 116607813654019,
        [4] = 138966229804486,
        [5] = 128961183894053,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "3جسم قزم",
  Callback = function()
local args = {
    [1] = {
        [1] = 120973199097564,
        [2] = 118345433416023,
        [3] = 112849465115864,
        [4] = 78321005147549,
        [5] = 106586789635639,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "جسم قزم",
  Callback = function()
local args = {
    [1] = {
        [1] = 126267841602936,
        [2] = 77530451194918,
        [3] = 123471958406889,
        [4] = 117042768644173,
        [5] = 131948590344338,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "الهامستر",
  Callback = function()
  local args = {
    [1] = {
        [1] = 14898536974,
        [2] = 14898536957,
        [3] = 14898537277,
        [4] = 14898537300,
        [5] = 14898537292,
        [6] = 14898536975
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})
local Main = MakeTab({Name = "التنقل"})
AddButton(Main, {
  Name = "اداة تنقل وين متريد توديك",
  Callback = function()
    local player = game.Players.LocalPlayer
    local mouse = player:GetMouse()

    local function createTeleportTool()
        local tool = Instance.new("Tool")
        tool.RequiresHandle = false
        tool.Name = " تنقل"

        tool.Activated:Connect(function()
            local hitPos = mouse.Hit.p + Vector3.new(0, 2.5, 0)
            local pos = CFrame.new(hitPos)
            player.Character.HumanoidRootPart.CFrame = pos
        end)

        tool.Parent = player.Backpack
    end

    -- Cria a ferramenta inicialmente
    createTeleportTool()

    -- Adiciona a ferramenta novamente quando o personagem é reaparecido
    player.CharacterAdded:Connect(function()
        wait(0.1) -- Espera um curto período de tempo para garantir que o inventário seja carregado
        createTeleportTool()
    end)
  end
})

AddButton(Main, {
    Name = "لوحة 1",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-242.68215942382812, 89.68680572509766, -549.6495361328125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

AddButton(Main, {
    Name = "لوحة 2",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-630.480712890625, 26.586822509765625, 365.14093017578125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

-- Function to teleport to Teleport
local function teleportToGasStation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(192, 4, 272)
end

AddButton(Main, {
    Name = "ورا البيوت",
    Description = "",
    Callback = teleportToGasStation
})

-- Function to teleport to Teleport
local function teleportToCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(136, 4, 117)
end

AddButton(Main, {
    Name = "قدام البيوت",
    Description = "",
    Callback = teleportToCenter
})

-- Function to teleport to Criminal
local function teleportToCriminal()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-119, -28, 235)
end

AddButton(Main, {
    Name = "مكان أسلحة",
    Description = "Teleporta para as coordenadas do Criminal",
    Callback = teleportToCriminal
})

-- Function to teleport to House Abandoned
local function teleportToHouseAbandoned()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(986, 4, 63)
end

AddButton(Main, {
    Name = "بيت قفير",
    Description = "Teleporta para as coordenadas da Casa Abandonada",
    Callback = teleportToHouseAbandoned
})

-- Function to teleport to Portal Agency
local function teleportToPortalAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(672, 4, -296)
end

AddButton(Main, {
    Name = "مكان سري",
    Description = "Teleporta para as coordenadas do Portal da Agência",
    Callback = teleportToPortalAgency
})

-- Function to teleport to Secret Location
local function teleportToSecretLocation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(505, -75, 143)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas do Local Secreto",
    Callback = teleportToSecretLocation
})

-- Function to teleport to School
local function teleportToSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-312, 4, 211)
end

AddButton(Main, {
    Name = "مدرسة",
    Description = "Teleporta para as coordenadas da Escola",
    Callback = teleportToSchool
})

-- Function to teleport to Brooks Diner
local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(161, 8, 52)
end

AddButton(Main, {
    Name = "قهوة",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})

local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-26, 4, -23)
end

AddButton(Main, {
    Name = "البداية",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})


-- Function to teleport to Hospital
local function teleportToHospital()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-309, 4, 71)
end

AddButton(Main, {
    Name = "مستشفى",
    Description = "Teleporta para as coordenadas do Hospital",
    Callback = teleportToHospital
})

-- Function to teleport to Arch
local function teleportToArch()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-589, 141, -59)
end

AddButton(Main, {
    Name = "فوق الجسر",
    Description = "Teleporta para as coordenadas do Arco",
    Callback = teleportToArch
})

-- Function to teleport to Agency
local function teleportToAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(179, 4, -464)
end

AddButton(Main, {
    Name = "مكان الكهرباء",
    Description = "Teleporta para as coordenadas da Agência",
    Callback = teleportToAgency
})

-- Function to teleport to Secret Room in Workshop
local function teleportToSecretRoomInWorkshop()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, 4, -495)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas da Sala Secreta na Oficina",
    Callback = teleportToSecretRoomInWorkshop
})

-- Function to teleport to Secret Room 2
local function teleportToSecretRoom2()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-343, 4, -613)
end

AddButton(Main, {
    Name = "جو الأرض 2",
    Description = "Teleporta para as coordenadas da Sala Secreta 2",
    Callback = teleportToSecretRoom2
})

-- Function to teleport to Island 1
local function teleportToIsland1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-1925, 23, 127)
end

AddButton(Main, {
    Name = "جزيرة 1",
    Description = "Teleporta para as coordenadas da Ilha 1",
    Callback = teleportToIsland1
})

-- Function to teleport to Airport
local function teleportToAirport()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(310, 5, 31)
end

AddButton(Main, {
    Name = "مطار",
    Description = "Teleporta para as coordenadas do Aeroporto",
    Callback = teleportToAirport
})

-- Function to teleport to Hotel Center
local function teleportToHotelCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(182, 4, 150)
end

AddButton(Main, {
    Name = "البيوت",
    Description = "Teleporta para as coordenadas do Centro dos Hotéis",
    Callback = teleportToHotelCenter
})

-- Function to teleport to Lower Houses
local function teleportToLowerHouses()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(63, 35, 410)
end

AddButton(Main, {
    Name = " نص الشارع",
    Description = "Teleporta para as coordenadas das Casas Inferiores",
    Callback = teleportToLowerHouses
})

-- Function to teleport to Mountain 1
local function teleportToMountain1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-670, 251, 765)
end

AddButton(Main, {
    Name = "فوق الجبل",
    Description = "Teleporta para as coordenadas da Montanha 1",
    Callback = teleportToMountain1
})

-- Function to teleport to On Top of School
local function teleportToOnTopOfSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-370, 50, 173)
end

AddButton(Main, {
    Name = "فوق المدرسة",
    Description = "Teleporta para as coordenadas Em Cima da Escola",
    Callback = teleportToOnTopOfSchool
})
local Main = MakeTab({Name = "االاعب"})
AddButton(Main, {
  Name = "Rejoin | اعادة دخول الى سيرفر",
  Callback = function()
    local ts = game:GetService("TeleportService")
				local p = game:GetService("Players").LocalPlayer
				ts:Teleport(game.PlaceId, p)
    print('Hello!')
  end
})
AddButton(Main, {
  Name = "احذف جميع الأشياء الي في ايدك",
  Callback = function()
    local args = {
    [1] = "ClearAllTools"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اقتل نفسك",
  Callback = function()
    game.Players.LocalPlayer.Character.Humanoid.Health = 0
  end
})
AddButton(Main, {
  Name = "ازالة لاق • Destroy Lag",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/CasperFlyModz/discord.gg-rips/main/FPSBooster.lua"))()
  end
})

AddTextBox(Main, {
  Name = "سرعة | Speed",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = value
 end
})
AddTextBox(Main, {
  Name = "قفز | Jump",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.JumpPower = value
  end
})
AddTextBox(Main, {
  Name = "Fov | شاشه",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
local FovNumber = value
local Camera = workspace.CurrentCamera
Camera.FieldOfView = FovNumber
  end
})
AddTextBox(Main, {
  Name = "Spin | دوران",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(Value)
    getgenv().Spinspeed = Value

local Spin = Instance.new'BodyAngularVelocity'
Spin.Parent = game:GetService'Players'.LocalPlayer.Character:FindFirstChild'HumanoidRootPart'
Spin.MaxTorque = Vector3.new(0, math.huge, 100)
wait(0.1)
Spin.AngularVelocity = Vector3.new(100,Spinspeed,0)
  end
})
AddButton(Main, {
  Name = "كنبه | Couch",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})
local infiniteJumpEnabled = false

-- Conectar o evento de pulo somente uma vez
local infiniteJumpConnection

-- Função de callback para o botão de alternância de pulo infinito
local function onInfiniteJumpToggle(value)
    infiniteJumpEnabled = value
    print("Infinite Jump Enabled:", infiniteJumpEnabled)

    -- Conectar o evento de pulo somente uma vez
    if not infiniteJumpConnection then
        infiniteJumpConnection = game:GetService("UserInputService").JumpRequest:Connect(function()
            if infiniteJumpEnabled then
                local player = game.Players.LocalPlayer
                local character = player.Character
                if character and character:FindFirstChildOfClass("Humanoid") then
                    character:FindFirstChildOfClass("Humanoid"):ChangeState("Jumping")
                end
            end
        end)
    end
end

-- Adiciona o botão de alternância "Infinitejum
    local Toggle = AddToggle(Main, {
    Name = "قفز لا نهائي | Inf Jump",
    Default = false,
    Callback = onInfiniteJumpToggle
})
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end

-- Variáveis e funções para a visualização dos jogadores
local viewEnabled = false
local selectedViewPlayer = nil
local characterAddedConnection = nil

local function toggleView(enabled)
    if enabled then
        if selectedViewPlayer then
            local player = selectedViewPlayer
            if player then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
                if characterAddedConnection then
                    characterAddedConnection:Disconnect()
                end
                characterAddedConnection = player.CharacterAdded:Connect(function(character)
                    game.Workspace.CurrentCamera.CameraSubject = character
                end)
                MakeNotifi({
                    Title = "Visualizando " .. player.Name,
                    Text = "Você está visualizando o jogador: " .. player.Name,
                    Time = 6
                })
            else
                print("Jogador não encontrado.")
                viewEnabled = false
            end
        else
            print("Nenhum jogador selecionado para a visualização.")
            viewEnabled = false
        end
    else
        if characterAddedConnection then
            characterAddedConnection:Disconnect()
            characterAddedConnection = nil
        end
        game.Workspace.CurrentCamera.CameraSubject = game.Players.LocalPlayer.Character
    end
end

local value = "" -- Variável para armazenar o nome digitado

local function findPlayerByPartialNameOrNickname(partialName)
    value = partialName -- Atualiza a variável com o nome digitado completo
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():find(partialName:lower(), 1, true) or (player.DisplayName and player.DisplayName:lower():find(partialName:lower(), 1, true)) then
            return player
        end
    end
    return nil
end

-- Adicionando a caixa de texto para entrada do nome ou apelido do jogador
AddTextBox(Main, {
    Name = " دخل اول ثلاث أحرف من اسم اللاعب",
    Default = "",
    PlaceholderText = "دخل اسم اللاعب",
    ClearText = true,
    Callback = function(value)
        if value == "" then
            MakeNotifi({
                Title = "Erro",
                Text = "Nome do jogador não foi digitado.",
                Time = 5
            })
            if viewEnabled then
                toggleView(false)
            end
            return
        end

        selectedViewPlayer = findPlayerByPartialNameOrNickname(value)
        if selectedViewPlayer then
            print("Jogador encontrado: " .. selectedViewPlayer.Name)
            if viewEnabled then
                toggleView(false)
                toggleView(true)
            end
        else
            MakeNotifi({
                Title = "Erro",
                Text = "Nenhum jogador encontrado com esse nome ou apelido.",
                Time = 7
            })
            if viewEnabled then
                toggleView(false)
            end
        end
    end
})

-- Adicionando o toggle para ativar/desativar a visualização
AddToggle(Main, {
    Name = "شاهد | View",
    Default = false,
    Callback = function(enabled)
        viewEnabled = enabled
        toggleView(enabled)
    end
})

-- Conectando eventos de jogador removido
game.Players.PlayerRemoving:Connect(function(player)
    if selectedViewPlayer == player then
        selectedViewPlayer = nil
        if viewEnabled then
            toggleView(false)
            MakeNotifi({
                Title = "Jogador Saiu",
                Text = player.Name .. " saiu do jogo. Visualização desativada.",
                Time = 5
            })
        end
    end
end)

-- Função para manter a câmera no jogador selecionado
local function maintainView()
    while wait() do
        if viewEnabled and selectedViewPlayer then
            local player = selectedViewPlayer
            if player and game.Workspace.CurrentCamera.CameraSubject ~= player.Character then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
            end
        end
    end
end
AddButton(Main, {
  Name = "اختفاء اللاعب",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 6
}
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "إلغاء اختفاء",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})
-- Variável para controlar o estado do Noclip
local noclipEnabled = false
local runService = game:GetService("RunService")

-- Função para definir CanCollide para todas as partes do personagem
local function setCharacterCanCollide(character, canCollide)
    for _, part in ipairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.CanCollide = canCollide
        end
    end
end

-- Função de callback para o botão de alternância de Noclip
local function onNoclipToggle(value)
    noclipEnabled = value
    print("Noclip Enabled:", noclipEnabled)

    local player = game.Players.LocalPlayer
    local character = player.Character

    if noclipEnabled then
        -- Inicia um loop para continuamente definir CanCollide
        noclipLoop = runService.Stepped:Connect(function()
            if character then
                setCharacterCanCollide(character, false)
            end
        end)
    else
        -- Desativa o loop e restaura CanCollide
        if noclipLoop then
            noclipLoop:Disconnect()
        end
        if character then
            setCharacterCanCollide(character, true)
        end
    end
end

-- Adiciona o botão de alternância "Noclip"
local Toggle = AddToggle(Main, {
    Name = " اختراق الجدار",
    Default = false,
    Callback = onNoclipToggle
})
AddButton(Main, {
  Name = "مسجل مجاني",
  Callback = function(s)
_G.boomboxb = game:GetObjects('rbxassetid://740618400')[1]
_G.boomboxb.Parent = game:GetService'Players'.LocalPlayer.Backpack
loadstring(_G.boomboxb.Client.Source)()
loadstring(_G.boomboxb.Server.Source)()
 end
})
local section = AddSection(Main, {"قتل بس قبله اخذ قنفة"})
AddButton(Main, {
  Name = "كنبة",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local player = playerService.LocalPlayer

-- Variáveis globais
local selectedPlayer = nil
local selectedKillAdvancedPlayer = nil
local couchEquipped = false
local playerDropdownV13

-- Função para obter a lista de jogadores
local function getPlayerList()
    local playerList = {}
    for _, player in ipairs(playerService:GetPlayers()) do
        if player ~= playerService.LocalPlayer then
            table.insert(playerList, player.Name)
        end
    end
    return playerList
end

-- Função para atualizar o dropdown
local function updateDropdown(dropdown)
    UpdateDropdown(dropdown, getPlayerList())
end

-- Função para encontrar jogador por nome
local function gplr(String)
    local strl = String:lower()
    local Found = {}
    for _, v in pairs(playerService:GetPlayers()) do
        if v.Name:lower():sub(1, #strl) == strl then
            table.insert(Found, v)
        end
    end
    return Found
end

-- Função para flingar jogador (V13)
local function flingPlayer(targetName)
    local Target = gplr(targetName)
    if Target[1] then
        Target = Target[1]

        local Thrust = Instance.new('BodyThrust', player.Character.HumanoidRootPart)
        Thrust.Force = Vector3.new(999, 999, 999)
        Thrust.Name = "FlingForce"
        repeat
            player.Character.HumanoidRootPart.CFrame = Target.Character.HumanoidRootPart.CFrame
            Thrust.Location = Target.Character.HumanoidRootPart.Position
            runService.Heartbeat:Wait()
        until not Target.Character:FindFirstChild("Head")
    end
end

-- Interface para Fling V13
playerDropdownV13 = AddDropdown(Main, {
    Name = "اختار الاعب الي تريده",
    Default = "",
    Options = getPlayerList(),
    Callback = function(value)
        selectedPlayer = value
    end
})

AddButton(Main, {
    Name = "قتل الاعب",
    Callback = function()
        if selectedPlayer then
            flingPlayer(selectedPlayer)
        end
    end
})

-- Atualiza a lista de jogadores quando os jogadores entram ou saem do jogo
playerService.PlayerAdded:Connect(function()
    updateDropdown(playerDropdownV13)
end)

playerService.PlayerRemoving:Connect(function()
    updateDropdown(playerDropdownV13)
end)

-- Atualiza a lista de jogadores ao iniciar o script
updateDropdown(playerDropdownV13)

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local localPlayer = playerService.LocalPlayer

-- Variáveis globais
local flingV14Toggle = false
local currentPlayerIndex = 1
local flingV14Connection
local players

-- Função para teleportar para a coordenada específica
local function teleportToCoordinate()
    local teleportPosition = Vector3.new(-58, 54, -183) -- Coordenada para onde você deseja teleportar
    if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
        localPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(teleportPosition)
    end
end

-- Função para flingar jogadores em sequência
local function flingPlayersInSequence()
    if flingV14Toggle then
        -- Obtém a lista de jogadores uma vez
        players = playerService:GetPlayers()

        -- Reseta o índice do jogador atual
        currentPlayerIndex = 1

        -- Looping de teleportes em cada jogador
        flingV14Connection = runService.Heartbeat:Connect(function()
            -- Ignora o jogador local
            while players[currentPlayerIndex] == localPlayer do
                currentPlayerIndex = currentPlayerIndex + 1
                if currentPlayerIndex > #players then
                    currentPlayerIndex = 1
                end
            end

            local targetPlayer = players[currentPlayerIndex]
            if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
                    localPlayer.Character.HumanoidRootPart.CFrame = targetPlayer.Character.HumanoidRootPart.CFrame

                    -- Verifica se o jogador alvo está sentado
                    if targetPlayer.Character:FindFirstChild("Humanoid") and targetPlayer.Character.Humanoid.SeatPart then
                        teleportToCoordinate()

                        -- Espera 3 segundos antes de ir para o próximo jogador
                        wait(5)
                        currentPlayerIndex = currentPlayerIndex + 1

                        if currentPlayerIndex > #players then
                            currentPlayerIndex = 1
                        end
                    end
                end
            end
        end)
    end
end

-- Função de callback para o toggle
local function onFlingV14Toggle(value)
    flingV14Toggle = value
    if flingV14Toggle then
        flingPlayersInSequence()
    else
        -- Desconecta as conexões quando o toggle é desativado
        if flingV14Connection then
            flingV14Connection:Disconnect()
            flingV14Connection = nil
        end
    end
end

-- Adiciona o Toggle para ativar/desativar o Fling V14
AddButton(Main, {
  Name = "☠️يعلق السيرفر☠️",
  Callback = function()
tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
AddButton(Main, {
  Name = "☠️تدمير العالم ☠️",
  Callback = function()
    game.Workspace:ClearAllChildren()
  end
})

AddButton(Main, {
  Name = "طرد الكل | kick all",
  Callback = function()
            tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")

local LocalPlayer = Players.LocalPlayer
local Camera = workspace.CurrentCamera
local flying = false
local speed = 50
local BodyGyro, BodyVelocity

local function Fly()
    local Character = LocalPlayer.Character
    if not Character or not Character:FindFirstChild("HumanoidRootPart") then return end
    local RootPart = Character:FindFirstChild("HumanoidRootPart")

    BodyGyro = Instance.new("BodyGyro", RootPart)
    BodyGyro.P = 9e4
    BodyGyro.maxTorque = Vector3.new(9e9, 9e9, 9e9)
    BodyGyro.CFrame = RootPart.CFrame

    BodyVelocity = Instance.new("BodyVelocity", RootPart)
    BodyVelocity.Velocity = Vector3.new(0, 0.1, 0)
    BodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)

    flying = true
    Character.Humanoid.PlatformStand = true

    RunService.RenderStepped:Connect(function()
        if flying then
            local MoveDirection = Character.Humanoid.MoveDirection
            local CameraDirection = Camera.CFrame.LookVector

            if MoveDirection.Magnitude > 0 then
                BodyVelocity.Velocity = (CameraDirection * MoveDirection.Magnitude) * speed
            else
                BodyVelocity.Velocity = Vector3.new(0, 0.1, 0)
            end

            BodyGyro.CFrame = Camera.CFrame
        end
    end)
end

local function StopFly()
    flying = false
    if BodyGyro then BodyGyro:Destroy() end
    if BodyVelocity then BodyVelocity:Destroy() end
    if LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("Humanoid") then
        LocalPlayer.Character.Humanoid.PlatformStand = false
    end
end

local Toggle = AddToggle(Main, {
    Name = "طيران",
    Default = false,
    Callback = function(Value)
        if Value then
            Fly()
        else
            StopFly()
        end
    end
})
local Main = MakeTab({Name = "كشفESP"})
local ESP = loadstring(game:HttpGet("https://kiriot22.com/releases/ESP.lua"))()
ESP:Toggle(true)
ESP.Players = false
ESP.Names = false

local Toggle = AddToggle(Main, {
  Name = "فعلة",
  Default = false,
  Callback = function(Value)
    ESP.Players = Value
  end
})

local Toggle = AddToggle(Main, {
  Name = "الاسامي الاعبين",
  Default = false,
  Callback = function(Value)
    ESP.Names = Value
  end
})
AddColorPicker(Main, {
  Name = "لون ESP ",
  Default = Color3.fromRGB(255, 255, 0),
  Callback = function(Value)
    ESP.Color = Value
  end
})

local Main = MakeTab({Name = "☠️الاسماء☠️"})
local colors = {
    Color3.fromRGB(255, 0, 0),
    Color3.fromRGB(255, 127, 0),
    Color3.fromRGB(255, 255, 0),
    Color3.fromRGB(0, 255, 0),
    Color3.fromRGB(0, 0, 255),
    Color3.fromRGB(75, 0, 130),
    Color3.fromRGB(148, 0, 211),
}

local rainbowRunning = false

AddButton(Main, {
    Name = "اسم ملون",
    Callback = function()
        if rainbowRunning then return end
        rainbowRunning = true

        task.spawn(function()
            while rainbowRunning do
                for _, color in ipairs(colors) do
                    local args = {
                        [1] = "PickingRPNameColor",
                        [2] = color,
                    }

                    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eColo1r"):FireServer(unpack(args))
                    task.wait(0.5) --
                end
            end
        end)
    end
})
AddTextBox(Main, {
    Name = "اسم",
    Default = "",
    PlaceholderText = "اكتب اسمك اهنا",
    ClearTextOnFocus = true,
    Callback = function(text)
        local args = {
            [1] = "RolePlayName",
            [2] = text
        }

        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
})
local section = AddSection(Main, {"☠️اسماء بنات☠️ "})

AddButton(Main, {
  Name = "شمس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْمَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نٌـوَرَ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نـِِـِـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "اسراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَسَرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "مريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْريمـْـْْـْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زهراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "زَهُرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "فََاَطْـمَِـهْ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "فََاَطْـمَِـهْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ليلى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "لُـِـِِـِِِـِِـِـيلُـِـِِـِِِـِِـِـﮯ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "تالين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تـٌـٌٌـآلُـِـِِـِِِـِِـِـينـِِـِـ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زينب",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ڒٍينـِِـِـبـٌـٌٌـٌٌٌـٌٌـٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌيُمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رقية",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌقُيُة"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نرجس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نرٍجٍسًٌُُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حور",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حـًـًًـًًًـًًـًـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْهُدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
local section = AddSection(Main, {"☠️اسماء اولاد☠️ "})
AddButton(Main, {
  Name = "ايتاشي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "آيتـٌـٌٌـآشُـُـُُـُي!"
}

AddButton(Main, {
  Name = "إآيَرٍيَن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "إآيَرٍيَن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مارتن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـآرٍتــن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مهدي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَهُدُيُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حسين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حَسَيُنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عـلـي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـلُـِـِِـِِِـِِـِـي"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "محمد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْحـًـًًـًًًـًًـًـمـْـْْـْڊ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوهان",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يُوٌهُأَنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "أَبَهُرٌ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَبَهُرٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سايكو",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَأَيُﮖوٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عباس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عُبَأَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "عمار",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـمـْـْْـْآر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شًـھﻤ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "A҉F҉K҉",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "A҉F҉K҉"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مرتضى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَرٌتَضِى"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوسف✨",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يَۈسًٌُُفَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "سجاد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَجِأَدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "توم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تَوٌمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

local Main = MakeTab({Name = "كيم باسات"})
AddButton(Main, {
  Name = "شات Premium",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  شات نجمه حقيقي",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.SilverPass.Value = true
  end
})
AddButton(Main, {
  Name = "نجمة",
  Callback = function()
 MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك نجمه",
  Time = 3
})
game:GetService("Players").LocalPlayer.PlayersBag.SilverPass.Value = true
  end
})
AddButton(Main, {
  Name = "نجمه مال اطفال",
  Callback = function()
 MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  نجمه مال اطفال ",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.FacePass.Value = true
  end
})
AddButton(Main, {
  Name = "اغاني",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  اغاني",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.MusicPass.Valve = true
  end
})
AddButton(Main, {
  Name = "Fire",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  Fire",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.FirePass.Valve = true
  end
})
local Main = MakeTab({Name = "اغاني"})
AddButton(Main, {
  Name = "اغنية حلوة",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "109188610023287"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سب 1",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "6536444735"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 2",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "8701632845"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 3",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "6713993281"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 4",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "5849978429"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 4",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "7183326833"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اكس اكس ",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "1836685799"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "Bigger Than Everything",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "15689446558"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اغنية عراقية",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "135009652401688"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اغنية عراقية 2",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "11463392143"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "وفيلنق ونسخ"})

AddSection(Main, {"سكربت نسخ سكنات"})
AddButton(Main, {
  Name = "سكربت نسخ قوي",
  Callback = function()
     loadstring(game:HttpGet("https://raw.githubusercontent.com/Luarmor123/YHUB-Community/refs/heads/main/BrookhavenCopyAvatar.lua"))()
  end
})
AddSection(Main, {"فيلنق"})

local Players = game:GetService("Players")
local Player = Players.LocalPlayer

local function GetPlayer(Name)
    Name = Name:lower()
    for _, x in next, Players:GetPlayers() do
        if x ~= Player then
            if x.Name:lower():match("^" .. Name) or x.DisplayName:lower():match("^" .. Name) then
                return x
            end
        end
    end
    return nil
end

local function Message(_Title, _Text, Time)
    game:GetService("StarterGui"):SetCore("SendNotification", {Title = _Title, Text = _Text, Duration = Time})
end

local function SkidFling(TargetPlayer)
    local Character = Player.Character
    local Humanoid = Character and Character:FindFirstChildOfClass("Humanoid")
    local RootPart = Humanoid and Humanoid.RootPart

    local TCharacter = TargetPlayer.Character
    local THumanoid = TCharacter and TCharacter:FindFirstChildOfClass("Humanoid")
    local TRootPart = THumanoid and THumanoid.RootPart
    local THead = TCharacter and TCharacter:FindFirstChild("Head")
    local Accessory = TCharacter and TCharacter:FindFirstChildOfClass("Accessory")
    local Handle = Accessory and Accessory:FindFirstChild("Handle")

    if Character and Humanoid and RootPart then
        if RootPart.Velocity.Magnitude < 50 then
            getgenv().OldPos = RootPart.CFrame
        end
        if THumanoid and THumanoid.Sit then
            return Message("Error Occurred", "Target is sitting", 5)
        end
        if THead then
            workspace.CurrentCamera.CameraSubject = THead
        elseif Handle then
            workspace.CurrentCamera.CameraSubject = Handle
        else
            workspace.CurrentCamera.CameraSubject = THumanoid
        end
        if not TCharacter:FindFirstChildWhichIsA("BasePart") then
            return
        end

        local function FPos(BasePart, Pos, Ang)
            RootPart.CFrame = CFrame.new(BasePart.Position) * Pos * Ang
            Character:SetPrimaryPartCFrame(CFrame.new(BasePart.Position) * Pos * Ang)
            RootPart.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
            RootPart.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
        end

        local function SFBasePart(BasePart)
            local TimeToWait = 2
            local Time = tick()
            local Angle = 0

            repeat
                if RootPart and THumanoid then
                    if BasePart.Velocity.Magnitude < 50 then
                        Angle = Angle + 100

                        FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle),0 ,0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(2.25, 1.5, -2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(-2.25, -1.5, 2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection,CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection,CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()
                    else
                        FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, -THumanoid.WalkSpeed), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, -TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5 ,0), CFrame.Angles(math.rad(-90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                        task.wait()
                    end
                else
                    break
                end
            until BasePart.Velocity.Magnitude > 500 or BasePart.Parent ~= TargetPlayer.Character or TargetPlayer.Parent ~= Players or not TargetPlayer.Character == TCharacter or THumanoid.Sit or Humanoid.Health <= 0 or tick() > Time + TimeToWait
        end

        workspace.FallenPartsDestroyHeight = 0/0

        local BV = Instance.new("BodyVelocity")
        BV.Name = "EpixVel"
        BV.Parent = RootPart
        BV.Velocity = Vector3.new(9e8, 9e8, 9e8)
        BV.MaxForce = Vector3.new(1/0, 1/0, 1/0)

        Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, false)

        if TRootPart and THead then
            if (TRootPart.CFrame.p - THead.CFrame.p).Magnitude > 5 then
                SFBasePart(THead)
            else
                SFBasePart(TRootPart)
            end
        elseif TRootPart and not THead then
            SFBasePart(TRootPart)
        elseif not TRootPart and THead then
            SFBasePart(THead)
        elseif not TRootPart and not THead and Accessory and Handle then
            SFBasePart(Handle)
        else
            return Message("Error Occurred", "Target is missing everything", 5)
        end

        BV:Destroy()
        Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
        workspace.CurrentCamera.CameraSubject = Humanoid

        repeat
            RootPart.CFrame = getgenv().OldPos * CFrame.new(0, .5, 0)
            Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, .5, 0))
            Humanoid:ChangeState("GettingUp")
            table.foreach(Character:GetChildren(), function(_, x)
                if x:IsA("BasePart") then
                    x.Velocity, x.RotVelocity = Vector3.new(), Vector3.new()
                end
            end)
            task.wait()
        until (RootPart.Position - getgenv().OldPos.p).Magnitude < 25
        workspace.FallenPartsDestroyHeight = getgenv().FPDH
    else
        return Message("Error Occurred", "Random error", 5)
    end
end

local playerNames = {}
for _, player in ipairs(Players:GetPlayers()) do
    if player ~= Player then
        table.insert(playerNames, player.Name)
    end
end

local selectedPlayer = nil

local Dropdown = AddDropdown(Main, {
    Name = "Select Player",
    Options = playerNames,
    Default = playerNames[1] or "",
    Callback = function(Value)
        selectedPlayer = GetPlayer(Value)
    end
})

local Toggle = AddToggle(Main, {
    Name = "Fling Player",
    Default = false,
    Callback = function(Value)
        if Value then
            if selectedPlayer then
                SkidFling(selectedPlayer)
            else
                Message("Error", "No player selected", 5)
            end
        end
    end
})


local Main = MakeTab({Name = "تخريب ماب"})
AddSection(Main, {"تخريب يطلع بس الك"})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
    local s = Instance.new("Sky")
    s.Name = "Sky"
    s.Parent = game.Lighting

    local skyboxID = 94946856358988
    local skyboxURL = "http://www.roblox.com/asset/?id="..skyboxID

    s.SkyboxBk = skyboxURL
    s.SkyboxDn = skyboxURL
    s.SkyboxFt = skyboxURL
    s.SkyboxLf = skyboxURL
    s.SkyboxRt = skyboxURL
    s.SkyboxUp = skyboxURL

    game.Lighting.TimeOfDay = "12:00:00"
  end
})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
  local decalID = 94946856358988
function exPro(root)
   for _, v in pairs(root:GetChildren()) do
      if v:IsA("Decal") and v.Texture ~= "http://www.roblox.com/asset/?id="..decalID then
         v.Parent = nil
      elseif v:IsA("BasePart") then
         v.Material = "Plastic"
         v.Transparency = 0
         for _, face in ipairs({"Front", "Back", "Right", "Left", "Top", "Bottom"}) do
            local d = Instance.new("Decal", v)
            d.Texture = "http://www.roblox.com/asset/?id="..decalID
            d.Face = face
         end
      end
      exPro(v)
   end
end

function asdf(root)
   for _, v in pairs(root:GetChildren()) do
      asdf(v)
   end
end

exPro(game.Workspace)
asdf(game.Workspace)
  end
})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
  -- Configuration --
local Message = "THIS GAME HAS BEEN HACKED BY CONCHKIDD"
local mes2text = "YOU ALL MUST PERISH IN MY FIRE OF DEATH!"

-- Don't touch unless you know what You're doing --

local mes = Instance.new("Hint")
mes.Parent = workspace
mes.Text = Message
game.Lighting:ClearAllChildren()
game.Lighting.FogEnd = 100
game.Lighting.FogColor = Color3.new(0, 0, 0)
local sound = Instance.new("Sound")
sound.Parent = workspace
sound.Looped = true
sound.PlaybackSpeed = 0.3
sound.Volume = 5
sound.SoundId = "rbxassetid://1842908121"
sound:Play()
local mes2 = Instance.new("Message")
mes2.Parent = workspace
mes2.Text = mes2text
for i, v in pairs(workspace:GetDescendants()) do
	if v:IsA("BasePart") and v.Parent:IsA("Model") then
		local outline = Instance.new("SelectionBox")
		v.Name = Message
		outline.Parent = v
		outline.Adornee = v
		outline.Color3 = Color3.new(1, 1, 1)
		v.Color = Color3.new(0, 0, 0)
		local fire = Instance.new("Fire")
		fire.Parent = v
		fire.Size = 100
		fire.Color = Color3.new(1, 1, 1)
		local sky = Instance.new("Sky")
		sky.CelestialBodiesShown = false
		sky.Parent = game.Lighting
		sky.SkyboxUp = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxBk = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxDn = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxRt = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxLf = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxFt = "http://www.roblox.com/asset/?id=99915080584370"
		local bill = Instance.new("BillboardGui")
		local Text = Instance.new("TextLabel")
		bill.Parent = v
		bill.Adornee = v
		bill.Size = UDim2.new(0, 200, 0, 200)
		Text.Parent = bill
		Text.Size = UDim2.new(0, 200, 0, 200)
		Text.BackgroundTransparency = 1
		Text.TextScaled = false
		Text.TextSize = 30
		Text.TextColor3 = Color3.new(1, 0, 0.0156863)
		Text.TextTransparency = 0
		Text.Font = Enum.Font.Cartoon
		Text.Text = Message
	end
end
  end
})
local Main = MakeTab({Name = "اكواد ملابس"})
AddButton(Main, {
  Name = "قفازات ايد سوداء",
  Callback = function()
  local args = {
    [1] = 9239689111
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سترة سوداء",
  Callback = function()
  local args = {
    [1] = 89892588488089
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سترة وردي كيوت",
  Callback = function()
  local args = {
    [1] = 10789914680
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 1",
  Callback = function()
  local args = {
    [1] = 10789914680
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 2",
  Callback = function()
  local args = {
    [1] = 11363898043
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 3",
  Callback = function()
  local args = {
    [1] = 10791180072
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد بيضة",
  Callback = function()
  local args = {
    [1] = 10871965173
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات يد زهري",
  Callback = function()
  local args = {
    [1] = 10789939838
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات يد حمراء",
  Callback = function()
  local args = {
    [1] = 12379676852
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "اضافر سوداء",
  Callback = function()
  local args = {
    [1] = 12825022709
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
`
            },
            {
                id: "Dark hub 2",
                name: "Dark hub 2",
                type: "lua",
                size: "87KB",
                downloads: "6.5K",
                category: "سجاد",

                content: `local args = {
    [1] = "RolePlayName",
    [2] = "مًطِوٌر آلَسِکْربًتٌ سِجّآدٍ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))

local args = {
    [1] = "RolePlayBio",
    [2] = ""
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))

local player = game.Players.LocalPlayer
local gui = Instance.new("ScreenGui", player:WaitForChild("PlayerGui"))
gui.Name = "DeltaWelcome"
gui.ResetOnSpawn = false

local main = Instance.new("Frame")
main.Parent = gui
main.AnchorPoint = Vector2.new(0.5, 0.5)
main.Position = UDim2.new(0.5, 0, 0.4, 0)
main.Size = UDim2.new(0, 450, 0, 150)
main.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
main.BackgroundTransparency = 0.2
main.BorderSizePixel = 0
main.Visible = false

local corner = Instance.new("UICorner", main)
corner.CornerRadius = UDim.new(0, 20)

-- الأيقونة على اليسار
local icon = Instance.new("ImageLabel", main)
icon.Size = UDim2.new(0, 60, 0, 60)
icon.Position = UDim2.new(0, 10, 0, 10)
icon.BackgroundTransparency = 1
icon.Image = "rbxassetid://131337234636792" -- غيّر الـID حسب رغبتك

-- النص
local text = Instance.new("TextLabel", main)
text.Size = UDim2.new(1, -80, 1, -20)
text.Position = UDim2.new(0, 80, 0, 10)
text.BackgroundTransparency = 1
text.Text = "مطور سكربت سجاد!"
text.TextColor3 = Color3.new(1, 1, 1)
text.Font = Enum.Font.GothamBold
text.TextScaled = true
text.TextWrapped = true
text.TextXAlignment = Enum.TextXAlignment.Left
text.TextYAlignment = Enum.TextYAlignment.Center

-- أنميشن الدخول
main.Visible = true
main.BackgroundTransparency = 1
text.TextTransparency = 1
icon.ImageTransparency = 1

for i = 1, 10 do
	main.BackgroundTransparency -= 0.08
	text.TextTransparency -= 0.1
	icon.ImageTransparency -= 0.1
	wait(0.03)
end

wait(5) -- كم ثانية تبقى

-- أنميشن الخروج
for i = 1, 10 do
	main.BackgroundTransparency += 0.08
	text.TextTransparency += 0.1
	icon.ImageTransparency += 0.1
	wait(0.03)
end

gui:Destroy()
wait(0.1)
game.StarterGui:SetCore("SendNotification", {
    Title = " جاري تشغيل";
    Text = "جاري تشغيل"; -- ARAB TEAM
    Duration = 5;
})
wait(0.1)
game.StarterGui:SetCore("SendNotification", {
    Title = " المطور سجاد";
    Text = "المطور سجاد"; -- ARAB TEAM
    Duration = 5;
})

loadstring(game:HttpGet(("https://raw.githubusercontent.com/Sadfffaj/-/refs/heads/main/%D8%AC%D8%A7%D8%B1%D9%8A%20%D8%AA%D8%B9%D9%84%D9%85%20%D8%A7%D9%84%D9%87.txt")))()
MakeWindow({
  Hub = {
    Title = "DARK HUH",
    Animation = "DARK HUH"
  },
    Key = {
    KeySystem = true,
    Title = "Key System",
    Description = "تلكه المفتاح بقناتي تلي ",
    KeyLink = "https://t.me/+Mr28iBIdzL40YzVi",
    Keys = {"SAD55"},
    Notifi = {
      Notifications = true,
      CorrectKey = "المفتاح صحيح",
      Incorrectkey = "المفتاح خطأ",
      CopyKeyLink = "تم النسخ في الحافظة"
    }
  }
})
MinimizeButton({
  Image = "rbxassetid://98360849741395",
  Size = {50, 50},
  Color = Color3.fromRGB(255, 125, 0),
  Corner = true,
  Stroke = false,
  StrokeColor = Color3.fromRGB(255, 125, 0)
})

local Main = MakeTab({Name = "معلومات"})
AddDiscord(Main, {
    DiscordLink = "https://t.me/+Mr28iBIdzL40YzVi",
    DiscordIcon = "rbxassetid://98360849741395",
    DiscordTitle = "انضم لقناتي لتعرف كلشي جديد",
    })
AddDiscord(Main, {
    DiscordLink = "https://discord.gg/SR9V8tDQDb",
    DiscordIcon = "rbxassetid://98360849741395",
    DiscordTitle = "انضم لسيرفرنا الديسكورد",
    })
AddButton(Main, {
  Name = "نسخ حسابي روبلوكس",
  Callback = function()
    setclipboard('SAGAD455')
  end
})
AddButton(Main, {
  Name = "نسخ حسابي تيك توك",
  Callback = function()
    setclipboard('8.9v3')
  end
})

local Main = MakeTab({Name = "كلشي وكلاشي"})

AddButton(Main, {
  Name = "رجل مقطوعه ",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رجل حديدة",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 17500249989,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس مخفي",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "راس روبوت",
  Callback = function()
    local args = {
    [1] = 3210773801
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس روكر",
  Callback = function()
    local args = {
    [1] = 134082579
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "راس كيوت",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 746767604
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
  local args = {
    [1] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

wait(0.1)
end
})
  AddButton(Main, {
  Name = " القزم",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = {
        [1] = 14579958702,
        [2] = 14579959062,
        [3] = 14579959191,
        [4] = 14579959249,
        [5] = 14579963667,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

wait(0.1)
  end
})
AddButton(Main, {
  Name = "قزومي",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 18599265011,
        [2] = 18599265151,
        [3] = 18599265190,
        [4] = 18599265270,
        [5] = 18599264796,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "عيون حادة",
  Callback = function()
  local args = {
    [1] = 16580493236
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

   end
})
AddButton(Main, {
  Name = "رجل العظام الرصاصي",
  Callback = function()
    print("Clicked")local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 17500249989,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "رجل العظام السود",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 14547162578,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "رجل رول",
  Callback = function()
    local args = {
    [1] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 3230472745,
        [5] = 3230470862,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جسم بنت ضعيف خصر",
  Callback = function()
local args = {
    [1] = {
        [1] = 74302534603111,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})


AddButton(Main, {
  Name = "بنية جسم",
  Callback = function()
local args = {
    [1] = {
        [1] = 96491916349570,
        [2] = 14854350570,
        [3] = 14854350451,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "بنت جسم",
  Callback = function()
local args = {
    [1] = {
        [1] = 16214246112,
        [2] = 16214249513,
        [3] = 16214251181,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
local args = {
    [1] = {
        [1] = 15539008532,
        [2] = 15539008875,
        [3] = 15539008680,
        [4] = 15539008795,
        [5] = 15539011945,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
local args = {
    [1] = {
        [1] = 14861800638,
        [2] = 14861800626,
        [3] = 14861801452,
        [4] = 14861800627,
        [5] = 14861801454,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم ولد",
  Callback = function()
local args = {
    [1] = {
        [1] = 17754346388,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم ولد ضعيفم",
  Callback = function()
local args = {
    [1] = {
        [1] = 92757812011061,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})


AddButton(Main, {
  Name = "جسم ولد كوبي",
  Callback = function()
local args = {
    [1] = {
        [1] = 86499666,
        [2] = 27112039,
        [3] = 27112052,
        [4] = 27112068,
        [5] = 27112056,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جسم ولد رول",
  Callback = function()
local args = {
    [1] = {
        [1] = 27112025,
        [2] = 27112039,
        [3] = 27112052,
        [4] = 3230472745,
        [5] = 3230470862,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "سيغما بوي",
  Callback = function()
local args = {
    [1] = {
        [1] = 18178775358,
        [2] = 18178775182,
        [3] = 18178775725,
        [4] = 18178777453,
        [5] = 18178775695,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

end})

AddButton(Main, {
  Name = "جسم قزم ",
  Callback = function()
local args = {
    [1] = {
        [1] = 14579958702,
        [2] = 14579959062,
        [3] = 14579959191,
        [4] = 14579959249,
        [5] = 14579963667,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})

AddButton(Main, {
  Name = "جسم قزم2",
  Callback = function()
local args = {
    [1] = {
        [1] = 77813057823038,
        [2] = 135110043370135,
        [3] = 116607813654019,
        [4] = 138966229804486,
        [5] = 128961183894053,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "3جسم قزم",
  Callback = function()
local args = {
    [1] = {
        [1] = 120973199097564,
        [2] = 118345433416023,
        [3] = 112849465115864,
        [4] = 78321005147549,
        [5] = 106586789635639,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "جسم قزم",
  Callback = function()
local args = {
    [1] = {
        [1] = 126267841602936,
        [2] = 77530451194918,
        [3] = 123471958406889,
        [4] = 117042768644173,
        [5] = 131948590344338,
        [6] = 1
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "الهامستر",
  Callback = function()
  local args = {
    [1] = {
        [1] = 14898536974,
        [2] = 14898536957,
        [3] = 14898537277,
        [4] = 14898537300,
        [5] = 14898537292,
        [6] = 14898536975
    }
}

game:GetService("ReplicatedStorage").Remotes.ChangeCharacterBody:InvokeServer(unpack(args))

  end
})
local Main = MakeTab({Name = "التنقل"})
AddButton(Main, {
  Name = "اداة تنقل وين متريد توديك",
  Callback = function()
    local player = game.Players.LocalPlayer
    local mouse = player:GetMouse()

    local function createTeleportTool()
        local tool = Instance.new("Tool")
        tool.RequiresHandle = false
        tool.Name = " تنقل"

        tool.Activated:Connect(function()
            local hitPos = mouse.Hit.p + Vector3.new(0, 2.5, 0)
            local pos = CFrame.new(hitPos)
            player.Character.HumanoidRootPart.CFrame = pos
        end)

        tool.Parent = player.Backpack
    end

    -- Cria a ferramenta inicialmente
    createTeleportTool()

    -- Adiciona a ferramenta novamente quando o personagem é reaparecido
    player.CharacterAdded:Connect(function()
        wait(0.1) -- Espera um curto período de tempo para garantir que o inventário seja carregado
        createTeleportTool()
    end)
  end
})

AddButton(Main, {
    Name = "لوحة 1",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-242.68215942382812, 89.68680572509766, -549.6495361328125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

AddButton(Main, {
    Name = "لوحة 2",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-630.480712890625, 26.586822509765625, 365.14093017578125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

-- Function to teleport to Teleport
local function teleportToGasStation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(192, 4, 272)
end

AddButton(Main, {
    Name = "ورا البيوت",
    Description = "",
    Callback = teleportToGasStation
})

-- Function to teleport to Teleport
local function teleportToCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(136, 4, 117)
end

AddButton(Main, {
    Name = "قدام البيوت",
    Description = "",
    Callback = teleportToCenter
})

-- Function to teleport to Criminal
local function teleportToCriminal()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-119, -28, 235)
end

AddButton(Main, {
    Name = "مكان أسلحة",
    Description = "Teleporta para as coordenadas do Criminal",
    Callback = teleportToCriminal
})

-- Function to teleport to House Abandoned
local function teleportToHouseAbandoned()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(986, 4, 63)
end

AddButton(Main, {
    Name = "بيت قفير",
    Description = "Teleporta para as coordenadas da Casa Abandonada",
    Callback = teleportToHouseAbandoned
})

-- Function to teleport to Portal Agency
local function teleportToPortalAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(672, 4, -296)
end

AddButton(Main, {
    Name = "مكان سري",
    Description = "Teleporta para as coordenadas do Portal da Agência",
    Callback = teleportToPortalAgency
})

-- Function to teleport to Secret Location
local function teleportToSecretLocation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(505, -75, 143)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas do Local Secreto",
    Callback = teleportToSecretLocation
})

-- Function to teleport to School
local function teleportToSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-312, 4, 211)
end

AddButton(Main, {
    Name = "مدرسة",
    Description = "Teleporta para as coordenadas da Escola",
    Callback = teleportToSchool
})

-- Function to teleport to Brooks Diner
local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(161, 8, 52)
end

AddButton(Main, {
    Name = "قهوة",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})

local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-26, 4, -23)
end

AddButton(Main, {
    Name = "البداية",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})


-- Function to teleport to Hospital
local function teleportToHospital()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-309, 4, 71)
end

AddButton(Main, {
    Name = "مستشفى",
    Description = "Teleporta para as coordenadas do Hospital",
    Callback = teleportToHospital
})

-- Function to teleport to Arch
local function teleportToArch()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-589, 141, -59)
end

AddButton(Main, {
    Name = "فوق الجسر",
    Description = "Teleporta para as coordenadas do Arco",
    Callback = teleportToArch
})

-- Function to teleport to Agency
local function teleportToAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(179, 4, -464)
end

AddButton(Main, {
    Name = "مكان الكهرباء",
    Description = "Teleporta para as coordenadas da Agência",
    Callback = teleportToAgency
})

-- Function to teleport to Secret Room in Workshop
local function teleportToSecretRoomInWorkshop()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, 4, -495)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas da Sala Secreta na Oficina",
    Callback = teleportToSecretRoomInWorkshop
})

-- Function to teleport to Secret Room 2
local function teleportToSecretRoom2()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-343, 4, -613)
end

AddButton(Main, {
    Name = "جو الأرض 2",
    Description = "Teleporta para as coordenadas da Sala Secreta 2",
    Callback = teleportToSecretRoom2
})

-- Function to teleport to Island 1
local function teleportToIsland1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-1925, 23, 127)
end

AddButton(Main, {
    Name = "جزيرة 1",
    Description = "Teleporta para as coordenadas da Ilha 1",
    Callback = teleportToIsland1
})

-- Function to teleport to Airport
local function teleportToAirport()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(310, 5, 31)
end

AddButton(Main, {
    Name = "مطار",
    Description = "Teleporta para as coordenadas do Aeroporto",
    Callback = teleportToAirport
})

-- Function to teleport to Hotel Center
local function teleportToHotelCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(182, 4, 150)
end

AddButton(Main, {
    Name = "البيوت",
    Description = "Teleporta para as coordenadas do Centro dos Hotéis",
    Callback = teleportToHotelCenter
})

-- Function to teleport to Lower Houses
local function teleportToLowerHouses()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(63, 35, 410)
end

AddButton(Main, {
    Name = " نص الشارع",
    Description = "Teleporta para as coordenadas das Casas Inferiores",
    Callback = teleportToLowerHouses
})

-- Function to teleport to Mountain 1
local function teleportToMountain1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-670, 251, 765)
end

AddButton(Main, {
    Name = "فوق الجبل",
    Description = "Teleporta para as coordenadas da Montanha 1",
    Callback = teleportToMountain1
})

-- Function to teleport to On Top of School
local function teleportToOnTopOfSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-370, 50, 173)
end

AddButton(Main, {
    Name = "فوق المدرسة",
    Description = "Teleporta para as coordenadas Em Cima da Escola",
    Callback = teleportToOnTopOfSchool
})
local Main = MakeTab({Name = "االاعب"})
AddButton(Main, {
  Name = "Rejoin | اعادة دخول الى سيرفر",
  Callback = function()
    local ts = game:GetService("TeleportService")
				local p = game:GetService("Players").LocalPlayer
				ts:Teleport(game.PlaceId, p)
    print('Hello!')
  end
})
AddButton(Main, {
  Name = "احذف جميع الأشياء الي في ايدك",
  Callback = function()
    local args = {
    [1] = "ClearAllTools"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اقتل نفسك",
  Callback = function()
    game.Players.LocalPlayer.Character.Humanoid.Health = 0
  end
})
AddButton(Main, {
  Name = "ازالة لاق • Destroy Lag",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/CasperFlyModz/discord.gg-rips/main/FPSBooster.lua"))()
  end
})

AddTextBox(Main, {
  Name = "سرعة | Speed",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = value
 end
})
AddTextBox(Main, {
  Name = "قفز | Jump",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.JumpPower = value
  end
})
AddTextBox(Main, {
  Name = "Fov | شاشه",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
local FovNumber = value
local Camera = workspace.CurrentCamera
Camera.FieldOfView = FovNumber
  end
})
AddTextBox(Main, {
  Name = "Spin | دوران",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(Value)
    getgenv().Spinspeed = Value

local Spin = Instance.new'BodyAngularVelocity'
Spin.Parent = game:GetService'Players'.LocalPlayer.Character:FindFirstChild'HumanoidRootPart'
Spin.MaxTorque = Vector3.new(0, math.huge, 100)
wait(0.1)
Spin.AngularVelocity = Vector3.new(100,Spinspeed,0)
  end
})
AddButton(Main, {
  Name = "كنبه | Couch",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})
local infiniteJumpEnabled = false

-- Conectar o evento de pulo somente uma vez
local infiniteJumpConnection

-- Função de callback para o botão de alternância de pulo infinito
local function onInfiniteJumpToggle(value)
    infiniteJumpEnabled = value
    print("Infinite Jump Enabled:", infiniteJumpEnabled)

    -- Conectar o evento de pulo somente uma vez
    if not infiniteJumpConnection then
        infiniteJumpConnection = game:GetService("UserInputService").JumpRequest:Connect(function()
            if infiniteJumpEnabled then
                local player = game.Players.LocalPlayer
                local character = player.Character
                if character and character:FindFirstChildOfClass("Humanoid") then
                    character:FindFirstChildOfClass("Humanoid"):ChangeState("Jumping")
                end
            end
        end)
    end
end

-- Adiciona o botão de alternância "Infinitejum
    local Toggle = AddToggle(Main, {
    Name = "قفز لا نهائي | Inf Jump",
    Default = false,
    Callback = onInfiniteJumpToggle
})
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end

-- Variáveis e funções para a visualização dos jogadores
local viewEnabled = false
local selectedViewPlayer = nil
local characterAddedConnection = nil

local function toggleView(enabled)
    if enabled then
        if selectedViewPlayer then
            local player = selectedViewPlayer
            if player then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
                if characterAddedConnection then
                    characterAddedConnection:Disconnect()
                end
                characterAddedConnection = player.CharacterAdded:Connect(function(character)
                    game.Workspace.CurrentCamera.CameraSubject = character
                end)
                MakeNotifi({
                    Title = "Visualizando " .. player.Name,
                    Text = "Você está visualizando o jogador: " .. player.Name,
                    Time = 6
                })
            else
                print("Jogador não encontrado.")
                viewEnabled = false
            end
        else
            print("Nenhum jogador selecionado para a visualização.")
            viewEnabled = false
        end
    else
        if characterAddedConnection then
            characterAddedConnection:Disconnect()
            characterAddedConnection = nil
        end
        game.Workspace.CurrentCamera.CameraSubject = game.Players.LocalPlayer.Character
    end
end

local value = "" -- Variável para armazenar o nome digitado

local function findPlayerByPartialNameOrNickname(partialName)
    value = partialName -- Atualiza a variável com o nome digitado completo
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():find(partialName:lower(), 1, true) or (player.DisplayName and player.DisplayName:lower():find(partialName:lower(), 1, true)) then
            return player
        end
    end
    return nil
end

-- Adicionando a caixa de texto para entrada do nome ou apelido do jogador
AddTextBox(Main, {
    Name = " دخل اول ثلاث أحرف من اسم اللاعب",
    Default = "",
    PlaceholderText = "دخل اسم اللاعب",
    ClearText = true,
    Callback = function(value)
        if value == "" then
            MakeNotifi({
                Title = "Erro",
                Text = "Nome do jogador não foi digitado.",
                Time = 5
            })
            if viewEnabled then
                toggleView(false)
            end
            return
        end

        selectedViewPlayer = findPlayerByPartialNameOrNickname(value)
        if selectedViewPlayer then
            print("Jogador encontrado: " .. selectedViewPlayer.Name)
            if viewEnabled then
                toggleView(false)
                toggleView(true)
            end
        else
            MakeNotifi({
                Title = "Erro",
                Text = "Nenhum jogador encontrado com esse nome ou apelido.",
                Time = 7
            })
            if viewEnabled then
                toggleView(false)
            end
        end
    end
})

-- Adicionando o toggle para ativar/desativar a visualização
AddToggle(Main, {
    Name = "شاهد | View",
    Default = false,
    Callback = function(enabled)
        viewEnabled = enabled
        toggleView(enabled)
    end
})

-- Conectando eventos de jogador removido
game.Players.PlayerRemoving:Connect(function(player)
    if selectedViewPlayer == player then
        selectedViewPlayer = nil
        if viewEnabled then
            toggleView(false)
            MakeNotifi({
                Title = "Jogador Saiu",
                Text = player.Name .. " saiu do jogo. Visualização desativada.",
                Time = 5
            })
        end
    end
end)

-- Função para manter a câmera no jogador selecionado
local function maintainView()
    while wait() do
        if viewEnabled and selectedViewPlayer then
            local player = selectedViewPlayer
            if player and game.Workspace.CurrentCamera.CameraSubject ~= player.Character then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
            end
        end
    end
end
AddButton(Main, {
  Name = "اختفاء اللاعب",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 6
}
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "إلغاء اختفاء",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})
-- Variável para controlar o estado do Noclip
local noclipEnabled = false
local runService = game:GetService("RunService")

-- Função para definir CanCollide para todas as partes do personagem
local function setCharacterCanCollide(character, canCollide)
    for _, part in ipairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.CanCollide = canCollide
        end
    end
end

-- Função de callback para o botão de alternância de Noclip
local function onNoclipToggle(value)
    noclipEnabled = value
    print("Noclip Enabled:", noclipEnabled)

    local player = game.Players.LocalPlayer
    local character = player.Character

    if noclipEnabled then
        -- Inicia um loop para continuamente definir CanCollide
        noclipLoop = runService.Stepped:Connect(function()
            if character then
                setCharacterCanCollide(character, false)
            end
        end)
    else
        -- Desativa o loop e restaura CanCollide
        if noclipLoop then
            noclipLoop:Disconnect()
        end
        if character then
            setCharacterCanCollide(character, true)
        end
    end
end

-- Adiciona o botão de alternância "Noclip"
local Toggle = AddToggle(Main, {
    Name = " اختراق الجدار",
    Default = false,
    Callback = onNoclipToggle
})
AddButton(Main, {
  Name = "مسجل مجاني",
  Callback = function(s)
_G.boomboxb = game:GetObjects('rbxassetid://740618400')[1]
_G.boomboxb.Parent = game:GetService'Players'.LocalPlayer.Backpack
loadstring(_G.boomboxb.Client.Source)()
loadstring(_G.boomboxb.Server.Source)()
 end
})
local section = AddSection(Main, {"قتل بس قبله اخذ قنفة"})
AddButton(Main, {
  Name = "كنبة",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local player = playerService.LocalPlayer

-- Variáveis globais
local selectedPlayer = nil
local selectedKillAdvancedPlayer = nil
local couchEquipped = false
local playerDropdownV13

-- Função para obter a lista de jogadores
local function getPlayerList()
    local playerList = {}
    for _, player in ipairs(playerService:GetPlayers()) do
        if player ~= playerService.LocalPlayer then
            table.insert(playerList, player.Name)
        end
    end
    return playerList
end

-- Função para atualizar o dropdown
local function updateDropdown(dropdown)
    UpdateDropdown(dropdown, getPlayerList())
end

-- Função para encontrar jogador por nome
local function gplr(String)
    local strl = String:lower()
    local Found = {}
    for _, v in pairs(playerService:GetPlayers()) do
        if v.Name:lower():sub(1, #strl) == strl then
            table.insert(Found, v)
        end
    end
    return Found
end

-- Função para flingar jogador (V13)
local function flingPlayer(targetName)
    local Target = gplr(targetName)
    if Target[1] then
        Target = Target[1]

        local Thrust = Instance.new('BodyThrust', player.Character.HumanoidRootPart)
        Thrust.Force = Vector3.new(999, 999, 999)
        Thrust.Name = "FlingForce"
        repeat
            player.Character.HumanoidRootPart.CFrame = Target.Character.HumanoidRootPart.CFrame
            Thrust.Location = Target.Character.HumanoidRootPart.Position
            runService.Heartbeat:Wait()
        until not Target.Character:FindFirstChild("Head")
    end
end

-- Interface para Fling V13
playerDropdownV13 = AddDropdown(Main, {
    Name = "اختار الاعب الي تريده",
    Default = "",
    Options = getPlayerList(),
    Callback = function(value)
        selectedPlayer = value
    end
})

AddButton(Main, {
    Name = "قتل الاعب",
    Callback = function()
        if selectedPlayer then
            flingPlayer(selectedPlayer)
        end
    end
})

-- Atualiza a lista de jogadores quando os jogadores entram ou saem do jogo
playerService.PlayerAdded:Connect(function()
    updateDropdown(playerDropdownV13)
end)

playerService.PlayerRemoving:Connect(function()
    updateDropdown(playerDropdownV13)
end)

-- Atualiza a lista de jogadores ao iniciar o script
updateDropdown(playerDropdownV13)

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local localPlayer = playerService.LocalPlayer

-- Variáveis globais
local flingV14Toggle = false
local currentPlayerIndex = 1
local flingV14Connection
local players

-- Função para teleportar para a coordenada específica
local function teleportToCoordinate()
    local teleportPosition = Vector3.new(-58, 54, -183) -- Coordenada para onde você deseja teleportar
    if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
        localPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(teleportPosition)
    end
end

-- Função para flingar jogadores em sequência
local function flingPlayersInSequence()
    if flingV14Toggle then
        -- Obtém a lista de jogadores uma vez
        players = playerService:GetPlayers()

        -- Reseta o índice do jogador atual
        currentPlayerIndex = 1

        -- Looping de teleportes em cada jogador
        flingV14Connection = runService.Heartbeat:Connect(function()
            -- Ignora o jogador local
            while players[currentPlayerIndex] == localPlayer do
                currentPlayerIndex = currentPlayerIndex + 1
                if currentPlayerIndex > #players then
                    currentPlayerIndex = 1
                end
            end

            local targetPlayer = players[currentPlayerIndex]
            if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
                    localPlayer.Character.HumanoidRootPart.CFrame = targetPlayer.Character.HumanoidRootPart.CFrame

                    -- Verifica se o jogador alvo está sentado
                    if targetPlayer.Character:FindFirstChild("Humanoid") and targetPlayer.Character.Humanoid.SeatPart then
                        teleportToCoordinate()

                        -- Espera 3 segundos antes de ir para o próximo jogador
                        wait(5)
                        currentPlayerIndex = currentPlayerIndex + 1

                        if currentPlayerIndex > #players then
                            currentPlayerIndex = 1
                        end
                    end
                end
            end
        end)
    end
end

-- Função de callback para o toggle
local function onFlingV14Toggle(value)
    flingV14Toggle = value
    if flingV14Toggle then
        flingPlayersInSequence()
    else
        -- Desconecta as conexões quando o toggle é desativado
        if flingV14Connection then
            flingV14Connection:Disconnect()
            flingV14Connection = nil
        end
    end
end

-- Adiciona o Toggle para ativar/desativar o Fling V14
AddButton(Main, {
  Name = "☠️يعلق السيرفر☠️",
  Callback = function()
tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
AddButton(Main, {
  Name = "☠️تدمير العالم ☠️",
  Callback = function()
    game.Workspace:ClearAllChildren()
  end
})

AddButton(Main, {
  Name = "طرد الكل | kick all",
  Callback = function()
            tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local RunService = game:GetService("RunService")

local LocalPlayer = Players.LocalPlayer
local Camera = workspace.CurrentCamera
local flying = false
local speed = 50
local BodyGyro, BodyVelocity

local function Fly()
    local Character = LocalPlayer.Character
    if not Character or not Character:FindFirstChild("HumanoidRootPart") then return end
    local RootPart = Character:FindFirstChild("HumanoidRootPart")

    BodyGyro = Instance.new("BodyGyro", RootPart)
    BodyGyro.P = 9e4
    BodyGyro.maxTorque = Vector3.new(9e9, 9e9, 9e9)
    BodyGyro.CFrame = RootPart.CFrame

    BodyVelocity = Instance.new("BodyVelocity", RootPart)
    BodyVelocity.Velocity = Vector3.new(0, 0.1, 0)
    BodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)

    flying = true
    Character.Humanoid.PlatformStand = true

    RunService.RenderStepped:Connect(function()
        if flying then
            local MoveDirection = Character.Humanoid.MoveDirection
            local CameraDirection = Camera.CFrame.LookVector

            if MoveDirection.Magnitude > 0 then
                BodyVelocity.Velocity = (CameraDirection * MoveDirection.Magnitude) * speed
            else
                BodyVelocity.Velocity = Vector3.new(0, 0.1, 0)
            end

            BodyGyro.CFrame = Camera.CFrame
        end
    end)
end

local function StopFly()
    flying = false
    if BodyGyro then BodyGyro:Destroy() end
    if BodyVelocity then BodyVelocity:Destroy() end
    if LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("Humanoid") then
        LocalPlayer.Character.Humanoid.PlatformStand = false
    end
end

local Toggle = AddToggle(Main, {
    Name = "طيران",
    Default = false,
    Callback = function(Value)
        if Value then
            Fly()
        else
            StopFly()
        end
    end
})
local Main = MakeTab({Name = "كشفESP"})
local ESP = loadstring(game:HttpGet("https://kiriot22.com/releases/ESP.lua"))()
ESP:Toggle(true)
ESP.Players = false
ESP.Names = false

local Toggle = AddToggle(Main, {
  Name = "فعلة",
  Default = false,
  Callback = function(Value)
    ESP.Players = Value
  end
})

local Toggle = AddToggle(Main, {
  Name = "الاسامي الاعبين",
  Default = false,
  Callback = function(Value)
    ESP.Names = Value
  end
})
AddColorPicker(Main, {
  Name = "لون ESP ",
  Default = Color3.fromRGB(255, 255, 0),
  Callback = function(Value)
    ESP.Color = Value
  end
})

local Main = MakeTab({Name = "☠️الاسماء☠️"})
local colors = {
    Color3.fromRGB(255, 0, 0),
    Color3.fromRGB(255, 127, 0),
    Color3.fromRGB(255, 255, 0),
    Color3.fromRGB(0, 255, 0),
    Color3.fromRGB(0, 0, 255),
    Color3.fromRGB(75, 0, 130),
    Color3.fromRGB(148, 0, 211),
}

local rainbowRunning = false

AddButton(Main, {
    Name = "اسم ملون",
    Callback = function()
        if rainbowRunning then return end
        rainbowRunning = true

        task.spawn(function()
            while rainbowRunning do
                for _, color in ipairs(colors) do
                    local args = {
                        [1] = "PickingRPNameColor",
                        [2] = color,
                    }

                    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eColo1r"):FireServer(unpack(args))
                    task.wait(0.5) --
                end
            end
        end)
    end
})
AddTextBox(Main, {
    Name = "اسم",
    Default = "",
    PlaceholderText = "اكتب اسمك اهنا",
    ClearTextOnFocus = true,
    Callback = function(text)
        local args = {
            [1] = "RolePlayName",
            [2] = text
        }

        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
})
local section = AddSection(Main, {"☠️اسماء بنات☠️ "})

AddButton(Main, {
  Name = "شمس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْمَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نٌـوَرَ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نـِِـِـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "اسراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَسَرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "مريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْريمـْـْْـْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زهراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "زَهُرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "فََاَطْـمَِـهْ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "فََاَطْـمَِـهْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ليلى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "لُـِـِِـِِِـِِـِـيلُـِـِِـِِِـِِـِـﮯ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "تالين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تـٌـٌٌـآلُـِـِِـِِِـِِـِـينـِِـِـ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زينب",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ڒٍينـِِـِـبـٌـٌٌـٌٌٌـٌٌـٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌيُمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رقية",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌقُيُة"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نرجس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نرٍجٍسًٌُُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حور",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حـًـًًـًًًـًًـًـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْهُدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
local section = AddSection(Main, {"☠️اسماء اولاد☠️ "})
AddButton(Main, {
  Name = "ايتاشي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "آيتـٌـٌٌـآشُـُـُُـُي!"
}

AddButton(Main, {
  Name = "إآيَرٍيَن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "إآيَرٍيَن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مارتن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـآرٍتــن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مهدي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَهُدُيُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حسين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حَسَيُنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عـلـي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـلُـِـِِـِِِـِِـِـي"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "محمد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْحـًـًًـًًًـًًـًـمـْـْْـْڊ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوهان",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يُوٌهُأَنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "أَبَهُرٌ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَبَهُرٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سايكو",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَأَيُﮖوٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عباس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عُبَأَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "عمار",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـمـْـْْـْآر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شًـھﻤ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "A҉F҉K҉",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "A҉F҉K҉"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مرتضى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَرٌتَضِى"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوسف✨",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يَۈسًٌُُفَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "سجاد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَجِأَدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "توم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تَوٌمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

local Main = MakeTab({Name = "كيم باسات"})
AddButton(Main, {
  Name = "شات Premium",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  شات نجمه حقيقي",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.SilverPass.Value = true
  end
})
AddButton(Main, {
  Name = "نجمة",
  Callback = function()
 MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك نجمه",
  Time = 3
})
game:GetService("Players").LocalPlayer.PlayersBag.SilverPass.Value = true
  end
})
AddButton(Main, {
  Name = "نجمه مال اطفال",
  Callback = function()
 MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  نجمه مال اطفال ",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.FacePass.Value = true
  end
})
AddButton(Main, {
  Name = "اغاني",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  اغاني",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.MusicPass.Valve = true
  end
})
AddButton(Main, {
  Name = "Fire",
  Callback = function()
MakeNotifi({
  Title = "DARK",
  Text = "تم صار عندك  Fire",
  Time = 3
})
 game:GetService("Players").LocalPlayer.PlayersBag.FirePass.Valve = true
  end
})
local Main = MakeTab({Name = "البيت | House"})

AddButton(Main, {
  Name = "  	كراج تفتحة وتسده",
  Callback = function()
					local args = {
						[1] = "GarageDoor"
					}
					game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
end
})




AddButton(Main, {
  Name = "  	شباك تفتحة  وتسده",
  Callback = function()
					local args = {
						[1] = "Curtains"
					}
					game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
end
})




AddButton(Main, {
  Name = "تحذف بيتك",
  Callback = function()
  local args = {
    [1] = "PlayerSellHouse"
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1eChoic1e"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "فتح",
  Callback = function()
  local args = {
    [1] = "LockDoors"
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))


  end
})
AddButton(Main, {
  Name = "قفل",
  Callback = function()
  local args = {
    [1] = "LockDoors"
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "لون بيتك ",
  Callback = function()
    local colors = {
      Color3.fromRGB(255, 0, 0),
      Color3.fromRGB(255, 127, 0),
      Color3.fromRGB(255, 255, 0),
      Color3.fromRGB(0, 255, 0),
      Color3.fromRGB(0, 0, 255),
      Color3.fromRGB(75, 0, 130),
      Color3.fromRGB(148, 0, 211)
    }

    local remote = game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e")


    while true do
      for _, color in ipairs(colors) do
        local args = {
          [1] = "ColorPickHouse",
          [2] = color
        }
        remote:FireServer(unpack(args))
        wait(0.5)
      end
    end
  end
})
AddTextBox(Main, {
    Name = "اسم",
    Default = "",
    PlaceholderText = "اكتب اسمك اهنا",
    Callback = function(value)
        local args = {
            [1] = "BusinessName",
            [2] = value
        }
        game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPHous1eEven1t"):FireServer(unpack(args))
    end
})
AddToggle(Main, {
    Name = "الغاء حظر عن بيت",
    Default = false,
    Callback = function(state)
        isUnbanActive = state
        if isUnbanActive then
            print(".")
            startAutoUnban()
        else
            print("تم فك الحظر")
        end
    end
})
function startAutoUnban()
    while isUnbanActive do
        for i, v in pairs(game:GetService("Workspace"):WaitForChild("001_Lots"):GetDescendants()) do
            -- houses
            if v.Name == "BannedBlock1" or v.Name == "BannedBlock2" or v.Name == "BannedBlock3" or v.Name == "BannedBlock4" or v.Name == "BannedBlock5" or v.Name == "BannedBlock6" or v.Name == "BannedBlock7" or v.Name == "BannedBlock11" or v.Name == "BannedBlock12" or v.Name == "BannedBlock13" or v.Name == "BannedBlock14" or v.Name == "BannedBlock15" or v.Name == "BannedBlock16" or v.Name == "BannedBlock17" or v.Name == "BannedBlock18" or v.Name == "BannedBlock19" or v.Name == "BannedBlock20" or v.Name == "BannedBlock21" or v.Name == "BannedBlock21" or v.Name == "BannedBlock22" or v.Name == "BannedBlock23" or v.Name == "BannedBlock24" or v.Name == "BannedBlock30" or v.Name == "BannedBlock31" or v.Name == "BannedBlock32" or v.Name == "BannedBlock33" or v.Name == "BannedBlock34" or v.Name == "BannedBlock35" then                -- destroy
                v:Destroy()
            end
        end
wait(1)
    end
end

AddButton(Main, {
  Name = "1 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "2 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 2
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "3 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 3
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "4 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 4
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "5 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 5
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "6 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 6
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "7 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 7
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "11 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 11
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "12 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 12
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "13 تاخذ تحكم البيت ",
  Callback = function()
    	local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 13
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "14 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 14
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "15 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 15
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "16 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 16
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "17 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 17
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "18 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 18
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "19 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 19
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "20 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 20
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "21 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 21
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "22 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 22
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "23 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 23
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "24 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 24
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 25",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 25
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 26",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 26
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 27",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 27
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 28",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 28
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 29",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 29
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 30",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 30
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 31",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 31
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 33",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 33
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 34",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 34
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 35",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 35
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 36",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 36
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "تحكم بيت 37",
  Callback = function()
  local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 37
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "اغاني"})
AddButton(Main, {
  Name = "اغنية حلوة",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "109188610023287"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سب 1",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "6536444735"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 2",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "8701632845"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 3",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "6713993281"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 4",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "5849978429"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سب 4",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "7183326833"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اكس اكس ",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "1836685799"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "Bigger Than Everything",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "15689446558"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اغنية عراقية",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "135009652401688"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اغنية عراقية 2",
  Callback = function()
     local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "11463392143"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "وفيلنق ونسخ"})

AddSection(Main, {"سكربت نسخ سكنات"})
AddButton(Main, {
  Name = "سكربت نسخ قوي",
  Callback = function()
     loadstring(game:HttpGet("https://raw.githubusercontent.com/Luarmor123/YHUB-Community/refs/heads/main/BrookhavenCopyAvatar.lua"))()
  end
})
AddSection(Main, {"فيلنق"})

local Players = game:GetService("Players")
local Player = Players.LocalPlayer

local function GetPlayer(Name)
    Name = Name:lower()
    for _, x in next, Players:GetPlayers() do
        if x ~= Player then
            if x.Name:lower():match("^" .. Name) or x.DisplayName:lower():match("^" .. Name) then
                return x
            end
        end
    end
    return nil
end

local function Message(_Title, _Text, Time)
    game:GetService("StarterGui"):SetCore("SendNotification", {Title = _Title, Text = _Text, Duration = Time})
end

local function SkidFling(TargetPlayer)
    local Character = Player.Character
    local Humanoid = Character and Character:FindFirstChildOfClass("Humanoid")
    local RootPart = Humanoid and Humanoid.RootPart

    local TCharacter = TargetPlayer.Character
    local THumanoid = TCharacter and TCharacter:FindFirstChildOfClass("Humanoid")
    local TRootPart = THumanoid and THumanoid.RootPart
    local THead = TCharacter and TCharacter:FindFirstChild("Head")
    local Accessory = TCharacter and TCharacter:FindFirstChildOfClass("Accessory")
    local Handle = Accessory and Accessory:FindFirstChild("Handle")

    if Character and Humanoid and RootPart then
        if RootPart.Velocity.Magnitude < 50 then
            getgenv().OldPos = RootPart.CFrame
        end
        if THumanoid and THumanoid.Sit then
            return Message("Error Occurred", "Target is sitting", 5)
        end
        if THead then
            workspace.CurrentCamera.CameraSubject = THead
        elseif Handle then
            workspace.CurrentCamera.CameraSubject = Handle
        else
            workspace.CurrentCamera.CameraSubject = THumanoid
        end
        if not TCharacter:FindFirstChildWhichIsA("BasePart") then
            return
        end

        local function FPos(BasePart, Pos, Ang)
            RootPart.CFrame = CFrame.new(BasePart.Position) * Pos * Ang
            Character:SetPrimaryPartCFrame(CFrame.new(BasePart.Position) * Pos * Ang)
            RootPart.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
            RootPart.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
        end

        local function SFBasePart(BasePart)
            local TimeToWait = 2
            local Time = tick()
            local Angle = 0

            repeat
                if RootPart and THumanoid then
                    if BasePart.Velocity.Magnitude < 50 then
                        Angle = Angle + 100

                        FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle),0 ,0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(2.25, 1.5, -2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(-2.25, -1.5, 2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection,CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection,CFrame.Angles(math.rad(Angle), 0, 0))
                        task.wait()
                    else
                        FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, -THumanoid.WalkSpeed), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, -TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(math.rad(90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5 ,0), CFrame.Angles(math.rad(-90), 0, 0))
                        task.wait()

                        FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                        task.wait()
                    end
                else
                    break
                end
            until BasePart.Velocity.Magnitude > 500 or BasePart.Parent ~= TargetPlayer.Character or TargetPlayer.Parent ~= Players or not TargetPlayer.Character == TCharacter or THumanoid.Sit or Humanoid.Health <= 0 or tick() > Time + TimeToWait
        end

        workspace.FallenPartsDestroyHeight = 0/0

        local BV = Instance.new("BodyVelocity")
        BV.Name = "EpixVel"
        BV.Parent = RootPart
        BV.Velocity = Vector3.new(9e8, 9e8, 9e8)
        BV.MaxForce = Vector3.new(1/0, 1/0, 1/0)

        Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, false)

        if TRootPart and THead then
            if (TRootPart.CFrame.p - THead.CFrame.p).Magnitude > 5 then
                SFBasePart(THead)
            else
                SFBasePart(TRootPart)
            end
        elseif TRootPart and not THead then
            SFBasePart(TRootPart)
        elseif not TRootPart and THead then
            SFBasePart(THead)
        elseif not TRootPart and not THead and Accessory and Handle then
            SFBasePart(Handle)
        else
            return Message("Error Occurred", "Target is missing everything", 5)
        end

        BV:Destroy()
        Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
        workspace.CurrentCamera.CameraSubject = Humanoid

        repeat
            RootPart.CFrame = getgenv().OldPos * CFrame.new(0, .5, 0)
            Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, .5, 0))
            Humanoid:ChangeState("GettingUp")
            table.foreach(Character:GetChildren(), function(_, x)
                if x:IsA("BasePart") then
                    x.Velocity, x.RotVelocity = Vector3.new(), Vector3.new()
                end
            end)
            task.wait()
        until (RootPart.Position - getgenv().OldPos.p).Magnitude < 25
        workspace.FallenPartsDestroyHeight = getgenv().FPDH
    else
        return Message("Error Occurred", "Random error", 5)
    end
end

local playerNames = {}
for _, player in ipairs(Players:GetPlayers()) do
    if player ~= Player then
        table.insert(playerNames, player.Name)
    end
end

local selectedPlayer = nil

local Dropdown = AddDropdown(Main, {
    Name = "Select Player",
    Options = playerNames,
    Default = playerNames[1] or "",
    Callback = function(Value)
        selectedPlayer = GetPlayer(Value)
    end
})

local Toggle = AddToggle(Main, {
    Name = "Fling Player",
    Default = false,
    Callback = function(Value)
        if Value then
            if selectedPlayer then
                SkidFling(selectedPlayer)
            else
                Message("Error", "No player selected", 5)
            end
        end
    end
})


local Main = MakeTab({Name = "تخريب ماب"})
AddSection(Main, {"تخريب يطلع بس الك"})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
    local s = Instance.new("Sky")
    s.Name = "Sky"
    s.Parent = game.Lighting

    local skyboxID = 94946856358988
    local skyboxURL = "http://www.roblox.com/asset/?id="..skyboxID

    s.SkyboxBk = skyboxURL
    s.SkyboxDn = skyboxURL
    s.SkyboxFt = skyboxURL
    s.SkyboxLf = skyboxURL
    s.SkyboxRt = skyboxURL
    s.SkyboxUp = skyboxURL

    game.Lighting.TimeOfDay = "12:00:00"
  end
})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
  local decalID = 94946856358988
function exPro(root)
   for _, v in pairs(root:GetChildren()) do
      if v:IsA("Decal") and v.Texture ~= "http://www.roblox.com/asset/?id="..decalID then
         v.Parent = nil
      elseif v:IsA("BasePart") then
         v.Material = "Plastic"
         v.Transparency = 0
         for _, face in ipairs({"Front", "Back", "Right", "Left", "Top", "Bottom"}) do
            local d = Instance.new("Decal", v)
            d.Texture = "http://www.roblox.com/asset/?id="..decalID
            d.Face = face
         end
      end
      exPro(v)
   end
end

function asdf(root)
   for _, v in pairs(root:GetChildren()) do
      asdf(v)
   end
end

exPro(game.Workspace)
asdf(game.Workspace)
  end
})
AddButton(Main, {
  Name = "تخريب",
  Callback = function()
  -- Configuration --
local Message = "THIS GAME HAS BEEN HACKED BY CONCHKIDD"
local mes2text = "YOU ALL MUST PERISH IN MY FIRE OF DEATH!"

-- Don't touch unless you know what You're doing --

local mes = Instance.new("Hint")
mes.Parent = workspace
mes.Text = Message
game.Lighting:ClearAllChildren()
game.Lighting.FogEnd = 100
game.Lighting.FogColor = Color3.new(0, 0, 0)
local sound = Instance.new("Sound")
sound.Parent = workspace
sound.Looped = true
sound.PlaybackSpeed = 0.3
sound.Volume = 5
sound.SoundId = "rbxassetid://1842908121"
sound:Play()
local mes2 = Instance.new("Message")
mes2.Parent = workspace
mes2.Text = mes2text
for i, v in pairs(workspace:GetDescendants()) do
	if v:IsA("BasePart") and v.Parent:IsA("Model") then
		local outline = Instance.new("SelectionBox")
		v.Name = Message
		outline.Parent = v
		outline.Adornee = v
		outline.Color3 = Color3.new(1, 1, 1)
		v.Color = Color3.new(0, 0, 0)
		local fire = Instance.new("Fire")
		fire.Parent = v
		fire.Size = 100
		fire.Color = Color3.new(1, 1, 1)
		local sky = Instance.new("Sky")
		sky.CelestialBodiesShown = false
		sky.Parent = game.Lighting
		sky.SkyboxUp = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxBk = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxDn = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxRt = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxLf = "http://www.roblox.com/asset/?id=99915080584370"
		sky.SkyboxFt = "http://www.roblox.com/asset/?id=99915080584370"
		local bill = Instance.new("BillboardGui")
		local Text = Instance.new("TextLabel")
		bill.Parent = v
		bill.Adornee = v
		bill.Size = UDim2.new(0, 200, 0, 200)
		Text.Parent = bill
		Text.Size = UDim2.new(0, 200, 0, 200)
		Text.BackgroundTransparency = 1
		Text.TextScaled = false
		Text.TextSize = 30
		Text.TextColor3 = Color3.new(1, 0, 0.0156863)
		Text.TextTransparency = 0
		Text.Font = Enum.Font.Cartoon
		Text.Text = Message
	end
end
  end
})
local Main = MakeTab({Name = "اكواد ملابس"})
AddButton(Main, {
  Name = "قفازات ايد سوداء",
  Callback = function()
  local args = {
    [1] = 9239689111
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سترة سوداء",
  Callback = function()
  local args = {
    [1] = 89892588488089
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "سترة وردي كيوت",
  Callback = function()
  local args = {
    [1] = 10789914680
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 1",
  Callback = function()
  local args = {
    [1] = 10789914680
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 2",
  Callback = function()
  local args = {
    [1] = 11363898043
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد سودة 3",
  Callback = function()
  local args = {
    [1] = 10791180072
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات ايد بيضة",
  Callback = function()
  local args = {
    [1] = 10871965173
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات يد زهري",
  Callback = function()
  local args = {
    [1] = 10789939838
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "قفازات يد حمراء",
  Callback = function()
  local args = {
    [1] = 12379676852
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "اضافر سوداء",
  Callback = function()
  local args = {
    [1] = 12825022709
}

game:GetService("ReplicatedStorage").Remotes.Wear:InvokeServer(unpack(args))

  end
})
`
            },
            {
                id: "Dark hub 3",
                name: "Dark hub 3",
                type: "txt",
                size: "78KB",
                description: "سكربت سجاد بحث : deep or drak hub",
                downloads: "4",
                category: "سجاد",
                content: `
loadstring(game:HttpGet(("https://raw.githubusercontent.com/R7KScript/usernaxo/refs/heads/main/GUI3")))()
MakeWindow({
  Hub = {
    Title = "DARK HUP",
    Animation = "DARK HUP"
  },
  Key = {
    KeySystem = false,
    Title = "Key System",
    Description = "",
    KeyLink = "",
    Keys = {"DARK"},
    Notifi = {
      Notifications = true,
      CorrectKey = "Running the Script...",
      Incorrectkey = "The key is incorrect",
      CopyKeyLink = "Copied to Clipboard"
    }
  }
})
MinimizeButton({
  Image = "rbxassetid://98360849741395",
  Size = {50, 50},
  Color = Color3.fromRGB(255, 125, 0),
  Corner = true,
  Stroke = false,
  StrokeColor = Color3.fromRGB(255, 125, 0)
})

local Main = MakeTab({Name = "تيليجرام"})
AddDiscord(Main, {
    DiscordLink = "https://t.me/SCN_key",
    DiscordIcon = "rbxassetid://98360849741395",
    DiscordTitle = "انضم لقناتي لتعرف كلشي جديد",
    })
AddButton(Main, {
  Name = "نسخ حسابي روبلوكس",
  Callback = function()
    setclipboard('SAGAD455')
  end
})
AddButton(Main, {
  Name = "نسخ حسابي تيك توك",
  Callback = function()
    setclipboard('8.9v3')
  end
})
local Main = MakeTab({Name = "كلشي وكلاشي"})

AddButton(Main, {
  Name = "رجل مقطوعه ",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رجل مقطوعه 2",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 139607673,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "راس مخفي",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "راس روبوت",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 3210773801
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "راس روكر",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 16580493236
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "راس كيوت",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 746767604
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "راس غريب",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 746774687
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "راس كبير",
  Callback = function()
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 616387160
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "جسم بنت",
  Callback = function()
  local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 86499698,
        [3] = 86499716,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
 }
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
end
})
  AddButton(Main, {
  Name = " القزم",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 14579958702,
        [2] = 14579959062,
        [3] = 14579959191,
        [4] = 14579959249,
        [5] = 14579963667,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})
AddButton(Main, {
  Name = "قزومي",
  Callback = function()
    print("Clicked")
    local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 18599265011,
        [2] = 18599265151,
        [3] = 18599265190,
        [4] = 18599265270,
        [5] = 18599264796,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
wait(0.1)
  end
})

AddButton(Main, {
  Name = "عيون حادة",
  Callback = function()
  local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 16580493236
    },
    [3] = "Roblox20"
    }
    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
   end
})
AddButton(Main, {
  Name = "رجل العظام الرصاصي",
  Callback = function()
    print("Clicked")local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 17500249989,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "رجل العظام السود",
  Callback = function()
    print("Clicked")local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 14547162578,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "رجل رول",
  Callback = function()
    print("Clicked")local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 3230472745,
        [5] = 1,
        [6] = 1
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "جسم ايمو",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 96491916349570,
[2] = 76683091425509,
[3] = 75159926897589,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "خصر ضعيف",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 74302534603111,
[2] = 76683091425509,
[3] = 75159926897589,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "بنية جسم",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 96491916349570,
[2] = 14854350570,
[3] = 14854350451,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "ايد القزومة",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 16214246112,
[2] = 16214249513,
[3] = 16214251181,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "بنت المنصور",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 15539008532,
[2] = 15539008875,
[3] = 15539008680,
[4] = 15539008795,
[5] = 15539011945,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "بنية صغيرة",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 14861800638,
[2] = 14861800626,
[3] = 14861801452,
[4] = 14861800627,
[5] = 14861801454,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "سمي الي يعجبك",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 17754346388,
[2] = 1,
[3] = 1,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "مسوي دايت جسم",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 92757812011061,
[2] = 99519402284266,
[3] = 115905570886697,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "كوبي جسم",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 86499666,
[2] = 27112039,
[3] = 27112052,
[4] = 27112068,
[5] = 27112056,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})


AddButton(Main, {
  Name = "رول قادح 🤯",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 27112025,
[2] = 27112039,
[3] = 27112052,
[4] = 3230472745,
[5] = 3230470862,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "سيغما بوي",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 18178775358,
[2] = 18178775182,
[3] = 18178775725,
[4] = 18178777453,
[5] = 18178775695,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "احبك",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 14579958702,
[2] = 14579959062,
[3] = 14579959191,
[4] = 14579959249,
[5] = 14579963667,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

end})

AddButton(Main, {
  Name = "يعني متوسط",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 77813057823038,
[2] = 135110043370135,
[3] = 116607813654019,
[4] = 138966229804486,
[5] = 128961183894053,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "كلش كصير",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 120973199097564,
[2] = 118345433416023,
[3] = 112849465115864,
[4] = 78321005147549,
[5] = 106586789635639,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "جسم قزم",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 126267841602936,
[2] = 77530451194918,
[3] = 123471958406889,
[4] = 117042768644173,
[5] = 131948590344338,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "هامستر جسم",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 14898536974,
[2] = 14898536957,
[3] = 14898537277,
[4] = 14898537300,
[5] = 14898537292,
[6] = 14898536975,
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

local Main = MakeTab({Name = "التنقل"})
AddButton(Main, {
  Name = "اداة تنقل وين متريد توديك",
  Callback = function()
    local player = game.Players.LocalPlayer
    local mouse = player:GetMouse()

    local function createTeleportTool()
        local tool = Instance.new("Tool")
        tool.RequiresHandle = false
        tool.Name = " تنقل"

        tool.Activated:Connect(function()
            local hitPos = mouse.Hit.p + Vector3.new(0, 2.5, 0)
            local pos = CFrame.new(hitPos)
            player.Character.HumanoidRootPart.CFrame = pos
        end)

        tool.Parent = player.Backpack
    end

    -- Cria a ferramenta inicialmente
    createTeleportTool()

    -- Adiciona a ferramenta novamente quando o personagem é reaparecido
    player.CharacterAdded:Connect(function()
        wait(0.1) -- Espera um curto período de tempo para garantir que o inventário seja carregado
        createTeleportTool()
    end)
  end
})

AddButton(Main, {
    Name = "لوحة 1",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-242.68215942382812, 89.68680572509766, -549.6495361328125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

AddButton(Main, {
    Name = "لوحة 2",
    Callback = function()
        local plr = game.Players.LocalPlayer
        local char = plr.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")

        if hrp then
            hrp.CFrame = CFrame.new(-630.480712890625, 26.586822509765625, 365.14093017578125)
        else
            warn("HumanoidRootPart not found")
        end
    end
})

-- Function to teleport to Teleport
local function teleportToGasStation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(192, 4, 272)
end

AddButton(Main, {
    Name = "ورا البيوت",
    Description = "",
    Callback = teleportToGasStation
})

-- Function to teleport to Teleport
local function teleportToCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(136, 4, 117)
end

AddButton(Main, {
    Name = "قدام البيوت",
    Description = "",
    Callback = teleportToCenter
})

-- Function to teleport to Criminal
local function teleportToCriminal()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-119, -28, 235)
end

AddButton(Main, {
    Name = "مكان أسلحة",
    Description = "Teleporta para as coordenadas do Criminal",
    Callback = teleportToCriminal
})

-- Function to teleport to House Abandoned
local function teleportToHouseAbandoned()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(986, 4, 63)
end

AddButton(Main, {
    Name = "بيت قفير",
    Description = "Teleporta para as coordenadas da Casa Abandonada",
    Callback = teleportToHouseAbandoned
})

-- Function to teleport to Portal Agency
local function teleportToPortalAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(672, 4, -296)
end

AddButton(Main, {
    Name = "مكان سري",
    Description = "Teleporta para as coordenadas do Portal da Agência",
    Callback = teleportToPortalAgency
})

-- Function to teleport to Secret Location
local function teleportToSecretLocation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(505, -75, 143)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas do Local Secreto",
    Callback = teleportToSecretLocation
})

-- Function to teleport to School
local function teleportToSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-312, 4, 211)
end

AddButton(Main, {
    Name = "مدرسة",
    Description = "Teleporta para as coordenadas da Escola",
    Callback = teleportToSchool
})

-- Function to teleport to Brooks Diner
local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(161, 8, 52)
end

AddButton(Main, {
    Name = "قهوة",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})

local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-26, 4, -23)
end

AddButton(Main, {
    Name = "البداية",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})


-- Function to teleport to Hospital
local function teleportToHospital()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-309, 4, 71)
end

AddButton(Main, {
    Name = "مستشفى",
    Description = "Teleporta para as coordenadas do Hospital",
    Callback = teleportToHospital
})

-- Function to teleport to Arch
local function teleportToArch()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-589, 141, -59)
end

AddButton(Main, {
    Name = "فوق الجسر",
    Description = "Teleporta para as coordenadas do Arco",
    Callback = teleportToArch
})

-- Function to teleport to Agency
local function teleportToAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(179, 4, -464)
end

AddButton(Main, {
    Name = "مكان الكهرباء",
    Description = "Teleporta para as coordenadas da Agência",
    Callback = teleportToAgency
})

-- Function to teleport to Secret Room in Workshop
local function teleportToSecretRoomInWorkshop()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, 4, -495)
end

AddButton(Main, {
    Name = "جو الأرض",
    Description = "Teleporta para as coordenadas da Sala Secreta na Oficina",
    Callback = teleportToSecretRoomInWorkshop
})

-- Function to teleport to Secret Room 2
local function teleportToSecretRoom2()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-343, 4, -613)
end

AddButton(Main, {
    Name = "جو الأرض 2",
    Description = "Teleporta para as coordenadas da Sala Secreta 2",
    Callback = teleportToSecretRoom2
})

-- Function to teleport to Island 1
local function teleportToIsland1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-1925, 23, 127)
end

AddButton(Main, {
    Name = "جزيرة 1",
    Description = "Teleporta para as coordenadas da Ilha 1",
    Callback = teleportToIsland1
})

-- Function to teleport to Airport
local function teleportToAirport()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(310, 5, 31)
end

AddButton(Main, {
    Name = "مطار",
    Description = "Teleporta para as coordenadas do Aeroporto",
    Callback = teleportToAirport
})

-- Function to teleport to Hotel Center
local function teleportToHotelCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(182, 4, 150)
end

AddButton(Main, {
    Name = "البيوت",
    Description = "Teleporta para as coordenadas do Centro dos Hotéis",
    Callback = teleportToHotelCenter
})

-- Function to teleport to Lower Houses
local function teleportToLowerHouses()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(63, 35, 410)
end

AddButton(Main, {
    Name = " نص الشارع",
    Description = "Teleporta para as coordenadas das Casas Inferiores",
    Callback = teleportToLowerHouses
})

-- Function to teleport to Mountain 1
local function teleportToMountain1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-670, 251, 765)
end

AddButton(Main, {
    Name = "فوق الجبل",
    Description = "Teleporta para as coordenadas da Montanha 1",
    Callback = teleportToMountain1
})

-- Function to teleport to On Top of School
local function teleportToOnTopOfSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-370, 50, 173)
end

AddButton(Main, {
    Name = "فوق المدرسة",
    Description = "Teleporta para as coordenadas Em Cima da Escola",
    Callback = teleportToOnTopOfSchool
})

local Main = MakeTab({Name = "البيت | House"})

AddButton(Main, {
  Name = "  	كراج تفتحة وتسده",
  Callback = function()
					local args = {
						[1] = "GarageDoor"
					}
					game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
end
})




AddButton(Main, {
  Name = "  	شباك تفتحة  وتسده",
  Callback = function()
					local args = {
						[1] = "Curtains"
					}
					game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
end
})



AddButton(Main, {
  Name = " قفل البيت",
  Callback = function()
					local args = {
						[1] = "LockDoors"
					}
					game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
end
})


AddButton(Main, {
  Name = "1 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "2 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 2
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "3 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 3
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "4 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 4
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "5 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 5
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "6 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 6
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "7 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 7
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "11 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 11
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "12 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 12
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "13 تاخذ تحكم البيت ",
  Callback = function()
    	local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 13
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "14 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 14
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "15 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 15
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "16 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 16
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "17 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 17
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "18 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 18
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "19 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 19
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "20 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 20
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "21 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 21
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "22 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 22
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "23 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 23
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "24 تاخذ تحكم البيت ",
  Callback = function()
    local args = {
    [1] = "GivePermissionLoopToServer",
    [2] = game:GetService("Players").LocalPlayer,
    [3] = 24
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "شغلات حلوة"})
AddButton(Main, {
  Name = "Rejoin | اعادة دخول الى سيرفر",
  Callback = function()
    local ts = game:GetService("TeleportService")
				local p = game:GetService("Players").LocalPlayer
				ts:Teleport(game.PlaceId, p)
    print('Hello!')
  end
})
AddButton(Main, {
  Name = "احذف جميع الأشياء الي في ايدك",
  Callback = function()
    local args = {
    [1] = "ClearAllTools"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اقتل نفسك",
  Callback = function()
    game.Players.LocalPlayer.Character.Humanoid.Health = 0
  end
})
AddButton(Main, {
  Name = "ازالة لاق • Destroy Lag",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/CasperFlyModz/discord.gg-rips/main/FPSBooster.lua"))()
  end
})
local Main = MakeTab({Name = "ادوات بوبجي"})
AddTextBox(Main, {
  Name = "سرعة | Speed",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = value
 end
})
AddTextBox(Main, {
  Name = "قفز | Jump",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.JumpPower = value
  end
})
AddTextBox(Main, {
  Name = "Fov | شاشه",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(value)
local FovNumber = value
local Camera = workspace.CurrentCamera
Camera.FieldOfView = FovNumber
  end
})
AddTextBox(Main, {
  Name = "Spin | دوران",
  Default = "",
  PlaceholderText = "ادخل رقم",
  ClearText = true,
  Callback = function(Value)
    getgenv().Spinspeed = Value

local Spin = Instance.new'BodyAngularVelocity'
Spin.Parent = game:GetService'Players'.LocalPlayer.Character:FindFirstChild'HumanoidRootPart'
Spin.MaxTorque = Vector3.new(0, math.huge, 100)
wait(0.1)
Spin.AngularVelocity = Vector3.new(100,Spinspeed,0)
  end
})
AddButton(Main, {
  Name = "كنبه | Couch",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})
local infiniteJumpEnabled = false

-- Conectar o evento de pulo somente uma vez
local infiniteJumpConnection

-- Função de callback para o botão de alternância de pulo infinito
local function onInfiniteJumpToggle(value)
    infiniteJumpEnabled = value
    print("Infinite Jump Enabled:", infiniteJumpEnabled)

    -- Conectar o evento de pulo somente uma vez
    if not infiniteJumpConnection then
        infiniteJumpConnection = game:GetService("UserInputService").JumpRequest:Connect(function()
            if infiniteJumpEnabled then
                local player = game.Players.LocalPlayer
                local character = player.Character
                if character and character:FindFirstChildOfClass("Humanoid") then
                    character:FindFirstChildOfClass("Humanoid"):ChangeState("Jumping")
                end
            end
        end)
    end
end

-- Adiciona o botão de alternância "Infinitejum
    local Toggle = AddToggle(Main, {
    Name = "قفز لا نهائي | Inf Jump",
    Default = false,
    Callback = onInfiniteJumpToggle
})
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end

-- Variáveis e funções para a visualização dos jogadores
local viewEnabled = false
local selectedViewPlayer = nil
local characterAddedConnection = nil

local function toggleView(enabled)
    if enabled then
        if selectedViewPlayer then
            local player = selectedViewPlayer
            if player then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
                if characterAddedConnection then
                    characterAddedConnection:Disconnect()
                end
                characterAddedConnection = player.CharacterAdded:Connect(function(character)
                    game.Workspace.CurrentCamera.CameraSubject = character
                end)
                MakeNotifi({
                    Title = "Visualizando " .. player.Name,
                    Text = "Você está visualizando o jogador: " .. player.Name,
                    Time = 6
                })
            else
                print("Jogador não encontrado.")
                viewEnabled = false
            end
        else
            print("Nenhum jogador selecionado para a visualização.")
            viewEnabled = false
        end
    else
        if characterAddedConnection then
            characterAddedConnection:Disconnect()
            characterAddedConnection = nil
        end
        game.Workspace.CurrentCamera.CameraSubject = game.Players.LocalPlayer.Character
    end
end

local value = "" -- Variável para armazenar o nome digitado

local function findPlayerByPartialNameOrNickname(partialName)
    value = partialName -- Atualiza a variável com o nome digitado completo
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():find(partialName:lower(), 1, true) or (player.DisplayName and player.DisplayName:lower():find(partialName:lower(), 1, true)) then
            return player
        end
    end
    return nil
end

-- Adicionando a caixa de texto para entrada do nome ou apelido do jogador
AddTextBox(Main, {
    Name = " دخل اول ثلاث أحرف من اسم اللاعب",
    Default = "",
    PlaceholderText = "دخل اسم اللاعب",
    ClearText = true,
    Callback = function(value)
        if value == "" then
            MakeNotifi({
                Title = "Erro",
                Text = "Nome do jogador não foi digitado.",
                Time = 5
            })
            if viewEnabled then
                toggleView(false)
            end
            return
        end

        selectedViewPlayer = findPlayerByPartialNameOrNickname(value)
        if selectedViewPlayer then
            print("Jogador encontrado: " .. selectedViewPlayer.Name)
            if viewEnabled then
                toggleView(false)
                toggleView(true)
            end
        else
            MakeNotifi({
                Title = "Erro",
                Text = "Nenhum jogador encontrado com esse nome ou apelido.",
                Time = 7
            })
            if viewEnabled then
                toggleView(false)
            end
        end
    end
})

-- Adicionando o toggle para ativar/desativar a visualização
AddToggle(Main, {
    Name = "شاهد | View",
    Default = false,
    Callback = function(enabled)
        viewEnabled = enabled
        toggleView(enabled)
    end
})

-- Conectando eventos de jogador removido
game.Players.PlayerRemoving:Connect(function(player)
    if selectedViewPlayer == player then
        selectedViewPlayer = nil
        if viewEnabled then
            toggleView(false)
            MakeNotifi({
                Title = "Jogador Saiu",
                Text = player.Name .. " saiu do jogo. Visualização desativada.",
                Time = 5
            })
        end
    end
end)

-- Função para manter a câmera no jogador selecionado
local function maintainView()
    while wait() do
        if viewEnabled and selectedViewPlayer then
            local player = selectedViewPlayer
            if player and game.Workspace.CurrentCamera.CameraSubject ~= player.Character then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
            end
        end
    end
end
AddButton(Main, {
  Name = "اختفاء اللاعب",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 6
}
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "إلغاء اختفاء",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})
-- Variável para controlar o estado do Noclip
local noclipEnabled = false
local runService = game:GetService("RunService")

-- Função para definir CanCollide para todas as partes do personagem
local function setCharacterCanCollide(character, canCollide)
    for _, part in ipairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.CanCollide = canCollide
        end
    end
end

-- Função de callback para o botão de alternância de Noclip
local function onNoclipToggle(value)
    noclipEnabled = value
    print("Noclip Enabled:", noclipEnabled)

    local player = game.Players.LocalPlayer
    local character = player.Character

    if noclipEnabled then
        -- Inicia um loop para continuamente definir CanCollide
        noclipLoop = runService.Stepped:Connect(function()
            if character then
                setCharacterCanCollide(character, false)
            end
        end)
    else
        -- Desativa o loop e restaura CanCollide
        if noclipLoop then
            noclipLoop:Disconnect()
        end
        if character then
            setCharacterCanCollide(character, true)
        end
    end
end

-- Adiciona o botão de alternância "Noclip"
local Toggle = AddToggle(Main, {
    Name = " اختراق الجدار",
    Default = false,
    Callback = onNoclipToggle
})
AddButton(Main, {
  Name = "مسجل مجاني",
  Callback = function(s)
_G.boomboxb = game:GetObjects('rbxassetid://740618400')[1]
_G.boomboxb.Parent = game:GetService'Players'.LocalPlayer.Backpack
loadstring(_G.boomboxb.Client.Source)()
loadstring(_G.boomboxb.Server.Source)()
 end
})
local section = AddSection(Main, {"قتل بس قبله اخذ قنفة"})
AddButton(Main, {
  Name = "كنبة",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local player = playerService.LocalPlayer

-- Variáveis globais
local selectedPlayer = nil
local selectedKillAdvancedPlayer = nil
local couchEquipped = false
local playerDropdownV13

-- Função para obter a lista de jogadores
local function getPlayerList()
    local playerList = {}
    for _, player in ipairs(playerService:GetPlayers()) do
        if player ~= playerService.LocalPlayer then
            table.insert(playerList, player.Name)
        end
    end
    return playerList
end

-- Função para atualizar o dropdown
local function updateDropdown(dropdown)
    UpdateDropdown(dropdown, getPlayerList())
end

-- Função para encontrar jogador por nome
local function gplr(String)
    local strl = String:lower()
    local Found = {}
    for _, v in pairs(playerService:GetPlayers()) do
        if v.Name:lower():sub(1, #strl) == strl then
            table.insert(Found, v)
        end
    end
    return Found
end

-- Função para flingar jogador (V13)
local function flingPlayer(targetName)
    local Target = gplr(targetName)
    if Target[1] then
        Target = Target[1]

        local Thrust = Instance.new('BodyThrust', player.Character.HumanoidRootPart)
        Thrust.Force = Vector3.new(999, 999, 999)
        Thrust.Name = "FlingForce"
        repeat
            player.Character.HumanoidRootPart.CFrame = Target.Character.HumanoidRootPart.CFrame
            Thrust.Location = Target.Character.HumanoidRootPart.Position
            runService.Heartbeat:Wait()
        until not Target.Character:FindFirstChild("Head")
    end
end

-- Interface para Fling V13
playerDropdownV13 = AddDropdown(Main, {
    Name = "اختار الاعب الي تريده",
    Default = "",
    Options = getPlayerList(),
    Callback = function(value)
        selectedPlayer = value
    end
})

AddButton(Main, {
    Name = "قتل الاعب",
    Callback = function()
        if selectedPlayer then
            flingPlayer(selectedPlayer)
        end
    end
})

-- Atualiza a lista de jogadores quando os jogadores entram ou saem do jogo
playerService.PlayerAdded:Connect(function()
    updateDropdown(playerDropdownV13)
end)

playerService.PlayerRemoving:Connect(function()
    updateDropdown(playerDropdownV13)
end)

-- Atualiza a lista de jogadores ao iniciar o script
updateDropdown(playerDropdownV13)

-- Serviços necessários
local playerService = game:GetService('Players')
local runService = game:GetService('RunService')
local localPlayer = playerService.LocalPlayer

-- Variáveis globais
local flingV14Toggle = false
local currentPlayerIndex = 1
local flingV14Connection
local players

-- Função para teleportar para a coordenada específica
local function teleportToCoordinate()
    local teleportPosition = Vector3.new(-58, 54, -183) -- Coordenada para onde você deseja teleportar
    if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
        localPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(teleportPosition)
    end
end

-- Função para flingar jogadores em sequência
local function flingPlayersInSequence()
    if flingV14Toggle then
        -- Obtém a lista de jogadores uma vez
        players = playerService:GetPlayers()

        -- Reseta o índice do jogador atual
        currentPlayerIndex = 1

        -- Looping de teleportes em cada jogador
        flingV14Connection = runService.Heartbeat:Connect(function()
            -- Ignora o jogador local
            while players[currentPlayerIndex] == localPlayer do
                currentPlayerIndex = currentPlayerIndex + 1
                if currentPlayerIndex > #players then
                    currentPlayerIndex = 1
                end
            end

            local targetPlayer = players[currentPlayerIndex]
            if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                if localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
                    localPlayer.Character.HumanoidRootPart.CFrame = targetPlayer.Character.HumanoidRootPart.CFrame

                    -- Verifica se o jogador alvo está sentado
                    if targetPlayer.Character:FindFirstChild("Humanoid") and targetPlayer.Character.Humanoid.SeatPart then
                        teleportToCoordinate()

                        -- Espera 3 segundos antes de ir para o próximo jogador
                        wait(5)
                        currentPlayerIndex = currentPlayerIndex + 1

                        if currentPlayerIndex > #players then
                            currentPlayerIndex = 1
                        end
                    end
                end
            end
        end)
    end
end

-- Função de callback para o toggle
local function onFlingV14Toggle(value)
    flingV14Toggle = value
    if flingV14Toggle then
        flingPlayersInSequence()
    else
        -- Desconecta as conexões quando o toggle é desativado
        if flingV14Connection then
            flingV14Connection:Disconnect()
            flingV14Connection = nil
        end
    end
end

-- Adiciona o Toggle para ativar/desativar o Fling V14
AddButton(Main, {
  Name = "☠️يعلق السيرفر☠️",
  Callback = function()
tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
AddButton(Main, {
  Name = "☠️تدمير العالم ☠️",
  Callback = function()
    game.Workspace:ClearAllChildren()
  end
})
AddButton(Main, {
  Name = "طرد الكل | kick all",
  Callback = function()
            tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
local Main = MakeTab({Name = "كشف هاذا اغاتي"})
local ESP = loadstring(game:HttpGet("https://kiriot22.com/releases/ESP.lua"))()
ESP:Toggle(true)
ESP.Players = false
ESP.Names = false

local Toggle = AddToggle(Main, {
  Name = "فعلة",
  Default = false,
  Callback = function(Value)
    ESP.Players = Value
  end
})

local Toggle = AddToggle(Main, {
  Name = "الاسامي الاعبين",
  Default = false,
  Callback = function(Value)
    ESP.Names = Value
  end
})
AddColorPicker(Main, {
  Name = "لون ESP ",
  Default = Color3.fromRGB(255, 255, 0),
  Callback = function(Value)
    ESP.Color = Value
  end
})

local Main = MakeTab({Name = "تطير"})
AddToggle(Main, {
    Name = "تطير الكل",
    Default = false,
    Callback = onFlingV14Toggle
})

-- Variável para armazenar a posição original do jogador
local originalPosition

-- Função para salvar a posição original do jogador
local function saveOriginalPosition()
    local character = game.Players.LocalPlayer.Character
    if character then
        originalPosition = character.HumanoidRootPart.CFrame
        print("Posição original salva:", originalPosition)
    else
        print("Erro ao salvar a posição original: personagem não encontrado.")
    end
end

-- Função para teleportar de volta para a posição original
local function teleportToOriginalPosition()
    local character = game.Players.LocalPlayer.Character
    if character and originalPosition then
        character.HumanoidRootPart.CFrame = originalPosition
        print("Teleportado de volta para a posição original!")
    else
        print("Erro ao teleportar de volta para a posição original.")
    end
end

-- Função para executar a ação de alerta com a arma
local function alarmGun()
    -- Salvar a posição original antes de teleportar
    saveOriginalPosition()

    -- Puxa o item Sniper
    local args = {
        [1] = "PickingTools",
        [2] = "Sniper"
    }
    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))

    -- Equipa o item Sniper
    local backpack = game.Players.LocalPlayer.Backpack
    local character = game.Players.LocalPlayer.Character

    local sniper = backpack:FindFirstChild("Sniper") or character:FindFirstChild("Sniper")

    if sniper then
        -- Se o item for encontrado, equipá-lo
        game.Players.LocalPlayer.Character.Humanoid:EquipTool(sniper)

        -- Salvar a posição atual do jogador
        local currentPosition = character.HumanoidRootPart.CFrame

        -- Teleportar o jogador para as coordenadas especificadas
        character.HumanoidRootPart.CFrame = CFrame.new(315, 5, 42)

        print("AlarmGun equipado e jogador teleportado!")

        -- Esperar um pouco antes de teleportar de volta para garantir que a animação seja concluída
        wait(2)

        -- Teleportar de volta para a posição original após usar a Sniper
        teleportToOriginalPosition()
    else
        -- Se o item não for encontrado, exibir uma mensagem de erro
        print("Sniper não encontrado no inventário ou personagem.")
    end
end
AddButton(Main, {
  Name = "تطير الناس",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
    loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe./main/Fling%20GUI"))()
  end
})
-- Kill Players
local targetPlayer = nil

local function findPlayerByName(partialName)
    local partial = partialName:sub(1, 2):lower()
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():sub(1, 2) == partial or (player.DisplayName and player.DisplayName:lower():sub(1, 2) == partial) then
            return player
        end
    end
    return nil
end

local function teleportAndKillPlayer(targetPlayer)
    if targetPlayer and targetPlayer.Character then
        local myHRP = game.Players.LocalPlayer.Character.HumanoidRootPart
        local targetHRP = targetPlayer.Character:WaitForChild("HumanoidRootPart")
        local connection
        connection = game:GetService("RunService").Stepped:Connect(function()
            myHRP.CFrame = targetHRP.CFrame
            if targetPlayer.Character and targetPlayer.Character:FindFirstChild("Humanoid") and targetPlayer.Character.Humanoid.Sit then
                myHRP.CFrame = CFrame.new(500000, 0, 0)
                connection:Disconnect()
            end
        end)
    end
end

local Main = MakeTab({Name = "☠️الاسماء☠️"})
local section = AddSection(Main, {"☠️اسماء بنات☠️ "})

AddButton(Main, {
  Name = "شمس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْمَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نٌـوَرَ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نـِِـِـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "اسراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَسَرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "مريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْريمـْـْْـْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زهراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "زَهُرٌأَء"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "فََاَطْـمَِـهْ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "فََاَطْـمَِـهْ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ليلى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "لُـِـِِـِِِـِِـِـيلُـِـِِـِِِـِِـِـﮯ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "تالين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تـٌـٌٌـآلُـِـِِـِِِـِِـِـينـِِـِـ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زينب",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ڒٍينـِِـِـبـٌـٌٌـٌٌٌـٌٌـٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ريم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌيُمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رقية",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رٌقُيُة"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "نرجس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نرٍجٍسًٌُُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حور",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حـًـًًـًًًـًًـًـوُر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شْهُدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
local section = AddSection(Main, {"☠️اسماء اولاد☠️ "})
AddButton(Main, {
  Name = "ايتاشي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "آيتـٌـٌٌـآشُـُـُُـُي!"
}

AddButton(Main, {
  Name = "إآيَرٍيَن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "إآيَرٍيَن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مارتن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـآرٍتــن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مهدي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَهُدُيُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "حسين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "حَسَيُنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عـلـي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـلُـِـِِـِِِـِِـِـي"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "محمد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـْـْْـْحـًـًًـًًًـًًـًـمـْـْْـْڊ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوهان",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يُوٌهُأَنِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "أَبَهُرٌ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أَبَهُرٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "سايكو",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَأَيُﮖوٌ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عباس",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عُبَأَسَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "عمار",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عٌـِـِِـِـمـْـْْـْآر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "شهم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شًـھﻤ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "A҉F҉K҉",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "A҉F҉K҉"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مرتضى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَرٌتَضِى"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "يوسف✨",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "يَۈسًٌُُفَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "سجاد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "سَجِأَدُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "توم",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "تَوٌمَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "☠️سكنات☠️"})
local Paragraph = AddParagraph(Main, {"☠️حذف كل الاشياء الي في اليد☠️"})
AddButton(Main, {
  Name = "☠️حذف كل الاشياء الي في اليد☠️",
  Callback = function()
    local args = {
    [1] = "ClearAllTools"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})

local Paragraph = AddParagraph(Main, {"☠️سكنات بنات☠️"})

AddButton(Main, {
  Name = "👩سكن بنت رقم [1]👩",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15701713751
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18509805623
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18744734552
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15222846056
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 101459562936324
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 17529187838
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 130491506065838
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 17444483167
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 16709737106
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15395115525
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14762227337
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 3210773801
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 7581474755
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 6174066797
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "👩سكن بنت حلو رقم [2]👩",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13307477554
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15795056785
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 12563952028
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 11156841853
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 17744851762
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 16139700318
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13133257230
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 116091391891300
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13620518518
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 3210773801
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18510929286
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 7675094321
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "👩سكن بنت رقم [3]👩",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 73569970599873
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 71333952559271
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 129864383052397
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 17744851762
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 122223238457929
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 88966032649180
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 127228549233812
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 9151422607
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18923672769
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 137160650691565
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 6238758375
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14402624573
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13900309877
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 96491916349570,
        [2] = 76683091425509,
        [3] = 75159926897589,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 3210773801
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 5981620229
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13329302128
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

local Paragraph = AddParagraph(Main, {"✨سكنات ولـد✨"})

AddButton(Main, {
  Name = "🧑سكن تنين ازرق رقم [1]🧑",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 4637265517,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14808924884
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15848163279
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 16127830905
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15535076528
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13575374227
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 11984960300
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 6433477241
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14659003969
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 7667832719
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 4637265517,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 3210773801
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "🧑سكن غـوجـو رقم [2]🧑",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 4637265517,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

local args = {
    [1] = "wear",
    [2] = 91078281931212
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15581867745
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 15188738427
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 121979595367770
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 4637265517,
        [2] = 99519402284266,
        [3] = 115905570886697,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "🧑سكن ولد S15 رقم [3]🧑",
  Callback = function()

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 139607718,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 17754346388,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

local args = {
    [1] = "wear",
    [2] = 140150480026352
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 82992820037885
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 13498671093
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 17386216598
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14774768752
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 81526836860931
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14832120928
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 14832124031
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 5727822995
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18594685747
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 18693879614
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(5.0)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 17754346388,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 1
    },
    [3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(3.7)

local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 1,
        [2] = 1,
        [3] = 1,
        [4] = 1,
        [5] = 1,
        [6] = 134082579
    },
    [3] = "Roblox20"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 83289659312825
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "wear",
    [2] = 12249790024
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(0.1)

local args = {
    [1] = "skintone",
    [2] = "Institutional white"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})
local Paragraph = AddParagraph(Main, {"شعر ولد دمج"})

AddButton(Main, {
  Name = "☠️اضغط لدمج الاسود☠️",
  Callback = function()

local args = {
    [1] = "wearWalkStyle",
    [2] = 14808924884
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15848163279
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 16127830905
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15535076528
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "☠️اضغط لدمج البني☠️",
  Callback = function()

local args = {
    [1] = "wearWalkStyle",
    [2] = 14627143022
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15294036713
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15847969469
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15971158257
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "☠️اضغط لدمج الابيض☠️",
  Callback = function()

local args = {
    [1] = "wearWalkStyle",
    [2] = 14627127264
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15908583844
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 14808889186
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

wait(1.0)

local args = {
    [1] = "wearWalkStyle",
    [2] = 15349539978
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))

  end
})`
            },
            {
                id: "alfa",
                name: "الفا",
                type: "txt",
                size: "114KB",
                description : "سكربت الفا بحث في الغيمه : الفا و alfa",
                category: "الفا",
                content: `shared.LoaderTitle = "جـارٍ تحـميـل سـكـربـت الـمـطـور آلـفـا ";
shared.LoaderKeyFrames = {
    [1] = {
        1,
        20
    },
    [2] = {
        2,
        50
    },
    [3] = {
        3,
        80
    },
    [4] = {
        2,
        100
    }
};
local v2 = {
    LoaderData = {
        Name = shared.LoaderTitle or "A Loader",
        Colors = shared.LoaderColors or {
            Main = Color3.fromRGB(0, 0, 0),
            Topic = Color3.fromRGB(7, 167, 0),
            Title = Color3.fromRGB(7, 167, 0),
            LoaderBackground = Color3.fromRGB(255, 255, 255),
            LoaderSplash = Color3.fromRGB(7, 167, 0)
        }
    },
    Keyframes = shared.LoaderKeyFrames or {
        [1] = {
            1,
            10
        },
        [2] = {
            2,
            30
        },
        [3] = {
            3,
            60
        },
        [4] = {
            2,
            100
        }
    }
};
local v3 = {
    [1] = "",
    [2] = "",
    [3] = "",
    [4] = ""
};
function TweenObject(v178, v179, v180)
    game.TweenService:Create(v178, TweenInfo.new(v179, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut), v180):Play();
end
function CreateObject(v181, v182)
    local v183 = Instance.new(v181);
    local v184;
    for v416, v417 in pairs(v182) do
        if (v416 ~= "Parent") then
            v183[v416] = v417;
        else
            v184 = v417;
        end
    end
    v183.Parent = v184;
    return v183;
end
local function v4(v186, v187)
    local v188 = Instance.new("UICorner");
    v188.CornerRadius = UDim.new(0, v186);
    v188.Parent = v187;
end
local v5 = CreateObject("ScreenGui", {
    Name = "Core",
    Parent = game.CoreGui
});
local v6 = CreateObject("Frame", {
    Name = "Main",
    Parent = v5,
    BackgroundColor3 = v2.LoaderData.Colors.Main,
    BorderSizePixel = 0,
    ClipsDescendants = true,
    Position = UDim2.new(0.5, 0, 0.5, 0),
    AnchorPoint = Vector2.new(0.5, 0.5),
    Size = UDim2.new(0, 0, 0, 0)
});
v4(12, v6);
local v7 = CreateObject("ImageLabel", {
    Name = "UserImage",
    Parent = v6,
    BackgroundTransparency = 1,
    Image = "rbxassetid://118236235426347",
    Position = UDim2.new(0, 15, 0, 10),
    Size = UDim2.new(0, 55, 0, 55)
});
v4(25, v7);
local v8 = CreateObject("TextLabel", {
    Name = "UserName",
    Parent = v6,
    BackgroundTransparency = 1,
    Text = "مـنـور الـسـكـربـت يا عـسل",
    Position = UDim2.new(0, 75, 0, 10),
    Size = UDim2.new(0, 200, 0, 50),
    Font = Enum.Font.GothamBold,
    TextColor3 = v2.LoaderData.Colors.Title,
    TextSize = 14,
    TextXAlignment = Enum.TextXAlignment.Left
});
local v9 = CreateObject("TextLabel", {
    Name = "Top",
    TextTransparency = 1,
    Parent = v6,
    BackgroundColor3 = Color3.fromRGB(255, 255, 255),
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 30, 0, 70),
    Size = UDim2.new(0, 301, 0, 20),
    Font = Enum.Font.Gotham,
    Text = "Loader",
    TextColor3 = v2.LoaderData.Colors.Topic,
    TextSize = 10,
    TextXAlignment = Enum.TextXAlignment.Left
});
local v10 = CreateObject("TextLabel", {
    Name = "Title",
    Parent = v6,
    TextTransparency = 1,
    BackgroundColor3 = Color3.fromRGB(255, 255, 255),
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 30, 0, 90),
    Size = UDim2.new(0, 301, 0, 46),
    Font = Enum.Font.Gotham,
    RichText = true,
    Text = "<b>" .. v2.LoaderData.Name .. "</b>",
    TextColor3 = v2.LoaderData.Colors.Title,
    TextSize = 14,
    TextXAlignment = Enum.TextXAlignment.Left
});
local v11 = CreateObject("Frame", {
    Name = "BG",
    Parent = v6,
    AnchorPoint = Vector2.new(0.5, 0),
    BackgroundTransparency = 1,
    BackgroundColor3 = v2.LoaderData.Colors.LoaderBackground,
    BorderSizePixel = 0,
    Position = UDim2.new(0.5, 0, 0, 70),
    Size = UDim2.new(0.8500000238418579, 0, 0, 24)
});
v4(8, v11);
local v12 = CreateObject("Frame", {
    Name = "Progress",
    Parent = v11,
    BackgroundColor3 = v2.LoaderData.Colors.LoaderSplash,
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Size = UDim2.new(0, 0, 0, 24)
});
v4(8, v12);
local v13 = CreateObject("TextLabel", {
    Name = "StepLabel",
    Parent = v6,
    BackgroundTransparency = 1,
    Position = UDim2.new(0.5, 0, 1, - 25),
    Size = UDim2.new(1, - 20, 0, 20),
    Font = Enum.Font.Gotham,
    Text = "",
    TextColor3 = v2.LoaderData.Colors.Topic,
    TextSize = 14,
    TextXAlignment = Enum.TextXAlignment.Center,
    AnchorPoint = Vector2.new(0.5, 0.5)
});
function UpdateStepText(v191)
    v13.Text = v3[v191] or "" ;
end
function UpdatePercentage(v193, v194)
    TweenObject(v12, 0.5, {
        Size = UDim2.new(v193 / 100, 0, 0, 24)
    });
    UpdateStepText(v194);
end
TweenObject(v6, 0.25, {
    Size = UDim2.new(0, 346, 0, 121)
});
wait();
TweenObject(v9, 0.5, {
    TextTransparency = 0
});
TweenObject(v10, 0.5, {
    TextTransparency = 0
});
TweenObject(v11, 0.5, {
    BackgroundTransparency = 0
});
TweenObject(v12, 0.5, {
    BackgroundTransparency = 0
});
for v195, v196 in pairs(v2.Keyframes) do
    wait(v196[1]);
    UpdatePercentage(v196[2], v195);
end
UpdatePercentage(100, 4);
TweenObject(v9, 0.5, {
    TextTransparency = 1
});
TweenObject(v10, 0.5, {
    TextTransparency = 1
});
TweenObject(v11, 0.5, {
    BackgroundTransparency = 1
});
TweenObject(v12, 0.5, {
    BackgroundTransparency = 1
});
wait(0.5);
TweenObject(v6, 0.25, {
    Size = UDim2.new(0, 0, 0, 0)
});
wait(0.25);
v5:Destroy();

local Sound = Instance.new("Sound", game:GetService("SoundService"));
Sound.SoundId = "rbxassetid://1";
Sound:Play();

game.Players.LocalPlayer.Character.Humanoid.Health = 0
wait(0.1)
game.StarterGui:SetCore("SendNotification", {
    Title = "ALFA ";
    Text = "-لـقـد تـم الـتـفـعـيل-"; -- ARAB TEAM
    Duration = 5;
})
game:GetService("ReplicatedStorage").RE["1RPNam1eTex1t"]:FireServer("RolePlayName", "-سڪـربـت الـمـطور آلـفـا V1.3-")

local args = {
    [1] = "PickingRPNameColor",
    [2] = Color3.fromRGB(7, 167, 0), -- Amarelo
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1RPNam1eColo1r"):FireServer(unpack(args))

local args = {
    [1] = "RolePlayBio",
    [2] ="-SCRIPT ALFA V1.3-"
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1RPNam1eTex1t"):FireServer(unpack(args))

local args = {
    [1] = "PickingRPBioColor",
    [2] = Color3.fromRGB(p, 0, 0), -- Amarelo
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1RPNam1eColo1r"):FireServer(unpack(args))
wait(0.5)
game.StarterGui:SetCore("SendNotification", {
    Title = "-تـم تـطـويـر الـسـكربـت مـن قبـل آلـفـا- ";
    Text = "-تـيـك  @آلفا- "; -- ARAB TEAM
    Duration = 5;
})

loadstring(game:HttpGet(("https://raw.githubusercontent.com/Martin19087/Martin/refs/heads/main/U")))()
MakeWindow({
  Hub = {
    Title = "SCRIPT ALFA V1.3",
    Animation = "SCRPIT ALFA V1.3 "
  },
  Key = {
    KeySystem = false,
    Title = "Key System",
    Description = "",
    KeyLink = "",
    Keys = {"1234"},
    Notifi = {
      Notifications = true,
      CorrectKey = "Running the Script...",
      Incorrectkey = "The key is incorrect",
      CopyKeyLink = "Copied to Clipboard"
    }
  }
})

MinimizeButton({
  Image = "rbxassetid://118236235426347",
  Size = {45, 45},
  Color = Color3.fromRGB(10, 10, 10),
  Corner = true,
  Stroke = true,
  StrokeColor = Color3.fromRGB(10, 10, 10)
})


local Main = MakeTab({Name = "الـمـعـلـومـات"})
local Image = AddImageLabel(Main, {
  Name = "الـمـطـور آلـفـا",
  Image = "rbxassetid://118236235426347"
})

AddButton(Main, {
  Name = "انـسـخ حـسـابـي تـيـك",
  Callback = function()
    setclipboard('آلفا')
  end
})

AddButton(Main, {
  Name = "انـسـخ حـسـابـي روب",
  Callback = function()
    setclipboard('zdrkn305')
  end
})

AddButton(Main, {
  Name = "انـسـخ حـسـاب الـطـور مـارتـن تـيـك",
  Callback = function()
    setclipboard('asf.69')
  end
})

AddButton(Main, {
  Name = "انـسـخ حـسـاب الـطـور مـارتـن روب",
  Callback = function()
    setclipboard('Dnawe1')
  end
})


local Main = MakeTab({Name = "الـسـڪربـتات"})



AddSection(Main, {"سـكربـت فـيـه كـل الـرقـصـات"})


AddButton(Main, {
  Name = "سـكربـت الـرقـصـات",
  Callback = function()
    loadstring(game:HttpGet("https://scriptblox.com/raw/Baseplate-Fe-All-Emote-7386"))()
  end
})


AddSection(Main, {"سـكربـت  تـخـريب و bang"})


AddButton(Main, {
  Name = "سـكربـت الـرحـمة",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/n0kc/AtomicHub/main/Map-Al-Biout.lua"))()
  end
})


AddSection(Main, {"سـكربـت  يـخـلي الـجـودة مـمـتازة"})


AddButton(Main, {
  Name = "سـكربـت جـودة",
  Callback = function()
    loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-Rtx-graphics-25102"))()
  end
})

AddSection(Main, {"سـكربـت يـخـلي الـسـيـارة تـطـير"})


AddButton(Main, {
  Name = "سـكربـت طـيـران السـيارة",
  Callback = function()
    loadstring(game:HttpGet("https://abre.ai/fly-gui"))();
  end
})


AddSection(Main, {"سـكربـت يـخـلي الـشـاشـة مـقـفـولـة"})


AddButton(Main, {
  Name = "سـكربـت قـفـل الـشـاشـة",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/Sector9922/SECTOR-SHIFT-LOCK/main/SECTOR%20SHIFT%20LOCK"))()
  end
})



AddSection(Main, {"سـكربـت  فـيـه حـركـة عـيـب"})


AddButton(Main, {
  Name = "سـكربـت ضـرب  +18",
  Callback = function()
    loadstring(game:HttpGet("https://pastefy.app/YZoglOyJ/raw"))()
  end
})



AddSection(Main, {"سـكربـت يـخـلي حـركـتـك سـريـعـة"})



AddButton(Main, {
  Name = "سـكربـت تـسـريـع",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe/main/obf_11l7Y131YqJjZ31QmV5L8pI23V02b3191sEg26E75472Wl78Vi8870jRv5txZyL1.lua.txt"))()
  end
})


AddSection(Main, {"سـكـربـت تـقـدر تـحـضـن الـنـاس"})


AddButton(Main, {
  Name = "سـكـربـت حـضـن",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/martinng5/martin/refs/heads/main/martin.lua.txt"))()
  end
})



AddSection(Main, {"سـكربـت  تـخـريب و اغـانـي"})


AddButton(Main, {
  Name = "R4D سـكربـت",
  Callback = function()
    loadstring(game:HttpGet("https://rawscripts.net/raw/Brookhaven-RP-R4D-Leak-12773"))()
  end
})

AddSection(Main, {"سـكربـت  يفـيـد بالـصـملات"})


AddButton(Main, {
  Name = "ghost سـكربـت",
  Callback = function()
    --Cl1f0nkid
loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-GhostHub-16534"))()
  end
})



AddSection(Main, {"سـكربـت فـيـه كـل شـيـئ تـتـخـيلـه"})


AddButton(Main, {
  Name = "universal سـكربـت",
  Callback = function()
    if "you wanna use rochips universal" then     local z_x,z_z="gzrux646yj/raw/main.ts","https://glot.io/snippets/"     local im,lonely,z_c=task.wait,game,loadstring     z_c(lonely:HttpGet(z_z..""..z_x))()     return ("This will load in about 2 - 30 seconds" or "according to your device and executor") end
  end
})
local Main = MakeTab({Name = "تـخـريـب"})


 AddSection(Main, {"قـتـل بـالـكـنبه"})


local Players = game:GetService('Players')
local lplayer = Players.LocalPlayer

function GetPlayer(String)
    local Found = {}
    local strl = String:lower()
    if strl == "all" then
        for _, v in pairs(Players:GetPlayers()) do
            table.insert(Found, v)
        end
    elseif strl == "others" then
        for _, v in pairs(Players:GetPlayers()) do
            if v.Name ~= lplayer.Name then
                table.insert(Found, v)
            end
        end
    elseif strl == "me" then
        table.insert(Found, lplayer)
    else
        for _, v in pairs(Players:GetPlayers()) do
            if v.Name:lower():sub(1, #String) == String:lower() then
                table.insert(Found, v)
            end
        end
    end
    return Found
end

local function isItemInInventory(itemName)
    for _, item in pairs(lplayer.Backpack:GetChildren()) do
        if item.Name == itemName then
            return true
        end
    end
    return false
end

local function equipItem(itemName)
    local item = lplayer.Backpack:FindFirstChild(itemName)
    if item then
        lplayer.Character.Humanoid:EquipTool(item)
    end
end

local function unequipItem(itemName)
    local item = lplayer.Character:FindFirstChild(itemName)
    if item then
        item.Parent = lplayer.Backpack
    end
end

local function ActiveAutoFling(targetPlayer)
    if not isItemInInventory("Couch") then
        local args = { [1] = "PickingTools", [2] = "Couch" }
        game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
    end

    equipItem("Couch")
    getgenv().flingloop = true

    while getgenv().flingloop do
        local function flingloopfix()
            local Players = game:GetService("Players")
            local Player = Players.LocalPlayer
            local AllBool = false

            local SkidFling = function(TargetPlayer)
                local Character = Player.Character
                local Humanoid = Character and Character:FindFirstChildOfClass("Humanoid")
                local RootPart = Humanoid and Humanoid.RootPart
                local TCharacter = TargetPlayer.Character
                local THumanoid, TRootPart, THead, Accessory, Handle

                if TCharacter:FindFirstChildOfClass("Humanoid") then
                    THumanoid = TCharacter:FindFirstChildOfClass("Humanoid")
                end
                if THumanoid and THumanoid.RootPart then
                    TRootPart = THumanoid.RootPart
                end
                if TCharacter:FindFirstChild("Head") then
                    THead = TCharacter.Head
                end
                if TCharacter:FindFirstChildOfClass("Accessory") then
                    Accessory = TCharacter:FindFirstChildOfClass("Accessory")
                end
                if Accessory and Accessory:FindFirstChild("Handle") then
                    Handle = Accessory.Handle
                end

                if Character and Humanoid and RootPart then
                    if RootPart.Velocity.Magnitude < 50 then
                        getgenv().OldPos = RootPart.CFrame
                    end
                    if THumanoid and THumanoid.Sit and not AllBool then
                        unequipItem("Couch")
                        getgenv().flingloop = false
                        return
                    end
                    if THead then
                        workspace.CurrentCamera.CameraSubject = THead
                    elseif not THead and Handle then
                        workspace.CurrentCamera.CameraSubject = Handle
                    elseif THumanoid and TRootPart then
                        workspace.CurrentCamera.CameraSubject = THumanoid
                    end

                    if not TCharacter:FindFirstChildWhichIsA("BasePart") then
                        return
                    end

                    local FPos = function(BasePart, Pos, Ang)
                        RootPart.CFrame = CFrame.new(BasePart.Position) * Pos * Ang
                        Character:SetPrimaryPartCFrame(CFrame.new(BasePart.Position) * Pos * Ang)
                        RootPart.Velocity = Vector3.new(9e7, 9e7 * 10, 9e7)
                        RootPart.RotVelocity = Vector3.new(9e8, 9e8, 9e8)
                    end

                    local SFBasePart = function(BasePart)
                        local TimeToWait = 2
                        local Time = tick()
                        local Angle = 0
                        repeat
                            if RootPart and THumanoid then
                                if BasePart.Velocity.Magnitude < 50 then
                                    Angle = Angle + 100
                                    FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(2.25, 1.5, -2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(-2.25, -1.5, 2.25) + THumanoid.MoveDirection * BasePart.Velocity.Magnitude / 1.25, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, 1.5, 0) + THumanoid.MoveDirection, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, 0) + THumanoid.MoveDirection, CFrame.Angles(math.rad(Angle), 0, 0))
                                    task.wait()
                                else
                                    FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, -THumanoid.WalkSpeed), CFrame.Angles(0, 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, 1.5, THumanoid.WalkSpeed), CFrame.Angles(math.rad(90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, -TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(0, 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, 1.5, TRootPart.Velocity.Magnitude / 1.25), CFrame.Angles(math.rad(90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(math.rad(90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5 ,0), CFrame.Angles(math.rad(-90), 0, 0))
                                    task.wait()
                                    FPos(BasePart, CFrame.new(0, -1.5, 0), CFrame.Angles(0, 0, 0))
                                    task.wait()
                                end
                            else
                                break
                            end
                        until BasePart.Velocity.Magnitude > 500 or BasePart.Parent ~= TargetPlayer.Character or TargetPlayer.Parent ~= Players or not TargetPlayer.Character == TCharacter or THumanoid.Sit or Humanoid.Health <= 0 or tick() > Time + TimeToWait or getgenv().flingloop == false
                    end

                    workspace.FallenPartsDestroyHeight = 0/0
                    local BV = Instance.new("BodyVelocity")
                    BV.Name = "SpeedDoPai"
                    BV.Parent = RootPart
                    BV.Velocity = Vector3.new(9e8, 9e8, 9e8)
                    BV.MaxForce = Vector3.new(1/0, 1/0, 1/0)
                    Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, false)

                    if TRootPart and THead then
                        if (TRootPart.CFrame.p - THead.CFrame.p).Magnitude > 5 then
                            SFBasePart(THead)
                        else
                            SFBasePart(TRootPart)
                        end
                    elseif TRootPart and not THead then
                        SFBasePart(TRootPart)
                    elseif not TRootPart and THead then
                        SFBasePart(THead)
                    elseif not TRootPart and not THead and Accessory and Handle then
                        SFBasePart(Handle)
                    end
                    BV:Destroy()
                    Humanoid:SetStateEnabled(Enum.HumanoidStateType.Seated, true)
                    workspace.CurrentCamera.CameraSubject = Humanoid

                    repeat
                        RootPart.CFrame = getgenv().OldPos * CFrame.new(0, .5, 0)
                        Character:SetPrimaryPartCFrame(getgenv().OldPos * CFrame.new(0, .5, 0))
                        Humanoid:ChangeState("GettingUp")
                        table.foreach(Character:GetChildren(), function(_, x)
                            if x:IsA("BasePart") then
                                x.Velocity, x.RotVelocity = Vector3.new(), Vector3.new()
                            end
                        end)
                        task.wait()
                    until (RootPart.Position - getgenv().OldPos.p).Magnitude < 25

                    workspace.FallenPartsDestroyHeight = getgenv().FPDH
                end
            end

            if not Welcome then
                -- Mensagem de boas-vindas
            end
            getgenv().Welcome = true

            if AllBool then
                for _, x in next, Players:GetPlayers() do
                    SkidFling(x)
                end
            end

            if targetPlayer then
                SkidFling(targetPlayer)
            end

            task.wait()
        end

        wait()
        pcall(flingloopfix)
    end
end

local FlingAdvancedPlayerList = {}
local playerDropdown

local function UMupdatePlayerList()
    FlingAdvancedPlayerList = {}
    for _, player in ipairs(Players:GetPlayers()) do
        table.insert(FlingAdvancedPlayerList, player.Name)
    end
    if playerDropdown then
        playerDropdown:Refresh(FlingAdvancedPlayerList, true)
    end
end

local function teleportToPlayer(playerName)
    local player = Players:FindFirstChild(playerName)
    local localPlayer = Players.LocalPlayer

    if player and player.Character and localPlayer.Character and localPlayer.Character:FindFirstChild("HumanoidRootPart") then
        local targetPosition = player.Character.HumanoidRootPart.Position
        localPlayer.Character:MoveTo(targetPosition)
        print("Teletransportado para o jogador alvo.")
    else
        print("NÃ£o foi possÃ­vel encontrar o jogador alvo ou o HumanoidRootPart.")
    end
end

UMupdatePlayerList()

AddDropdown(Main, {
    Name = "اخـتـار الـلاعـب",
    Default = "",
    Options = FlingAdvancedPlayerList,
    Callback = function(value)
        SelectedPlayer = value
    end
})


local flingToggle

AddToggle(Main, {
    Name = "قـتـل الـلاعـب بـالـكنـبة",
    Default = false,
    Callback = function(state)
        if state then
            if SelectedPlayer then
                local targetPlayer = GetPlayer(SelectedPlayer)[1]
                if targetPlayer then
                    ActiveAutoFling(targetPlayer)
                end
            end
        else
            getgenv().flingloop = false
        end
    end
})

game:GetService("Players").LocalPlayer.Character.Humanoid:GetPropertyChangedSignal("Sit"):Connect(function()
    if lplayer.Character.Humanoid.Sit then
        if flingToggle then
            flingToggle:Set(false)
        end
    end
end)


AddSection(Main, {"قـتـل بـالـسيـارة الـسـوداء"})


local Players = game:GetService("Players")

local playerNames = {}
for _, player in ipairs(Players:GetPlayers()) do
    table.insert(playerNames, player.Name)
end

local selectedCarPlayer

AddDropdown(Main, {
    Name = "اخـتـار الـلاعـب",
    Options = playerNames,
    Callback = function(selected)
        selectedCarPlayer = selected
    end
})

AddButton(Main, {
    Name = "قـتـل الـلاعـب بـالـسيـارة",
    Callback = function()
        if not selectedCarPlayer then
            return
        end

        local player = Players.LocalPlayer
        local character = player.Character or player.CharacterAdded:Wait()
        local humanoidRootPart = character:WaitForChild("HumanoidRootPart")
        local originalPosition = humanoidRootPart.CFrame

        local function GetCar()
            local vehicles = workspace:FindFirstChild("Vehicles")
            if vehicles then
                return vehicles:FindFirstChild(player.Name.."Car")
            end
            return nil
        end

        local car = GetCar()
        if not car then
            humanoidRootPart.CFrame = CFrame.new(1118.81, 75.998, -1138.61)
            task.wait(0.5)
            local remoteEvent = game:GetService("ReplicatedStorage"):FindFirstChild("RE")
            if remoteEvent and remoteEvent:FindFirstChild("1Ca1r") then
                remoteEvent["1Ca1r"]:FireServer("PickingCar", "TowTruck")
            end
            task.wait(1)
            car = GetCar()
        end

        if car then
            local seat = car:FindFirstChild("Body") and car.Body:FindFirstChild("VehicleSeat")
            if seat and character:FindFirstChildOfClass("Humanoid") and not character.Humanoid.Sit then
                repeat
                    humanoidRootPart.CFrame = seat.CFrame * CFrame.new(0, 2, 0)
                    task.wait()
                until character.Humanoid.Sit or not car.Parent
            end
        end

        local destination = Vector3.new(265.46, -450.83, -59.93)
        spawn(function()
            while true do
                if selectedCarPlayer then
                    local targetPlayer = Players:FindFirstChild(selectedCarPlayer)
                    if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                        local targetHumanoid = targetPlayer.Character:FindFirstChildOfClass("Humanoid")
                        if targetHumanoid and targetHumanoid.Sit then
                            if character.Humanoid then
                                car:SetPrimaryPartCFrame(CFrame.new(destination))
                                task.wait(0.2)
                                character.Humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
                                task.wait(0.5)
                                humanoidRootPart.CFrame = originalPosition
                            end
                            break
                        else
                            local targetRoot = targetPlayer.Character.HumanoidRootPart
                            local offset = math.sin(tick() * 32) * 8
                            car:SetPrimaryPartCFrame(targetRoot.CFrame * CFrame.new(0, 0, -2) * CFrame.new(offset, 0, -2))
                        end
                    end
                end
                game:GetService("RunService").RenderStepped:Wait()
            end
        end)
    end
})



AddSection(Main, {"قـتـل بـالـسـفـيـنـة"})

local Players = game:GetService("Players")
local playerNames = {}
for _, player in pairs(Players:GetPlayers()) do
    table.insert(playerNames, player.Name)
end

local selectedBoatPlayer = nil

AddDropdown(Main, {
    Name = "اخـتـار الـلاعـب",
    Options = playerNames,
    Callback = function(selected)
        selectedBoatPlayer = selected
    end
})

AddButton(Main, {
    Name = "اقـتـل الـلاعـب بـالـسـفيـنـة",
    Callback = function()
        if not selectedBoatPlayer then
            print("لا يوجد لاعب محدد!")
            return
        end

        local player = Players.LocalPlayer
        local character = player.Character or player.CharacterAdded:Wait()
        local humanoid = character:WaitForChild("Humanoid")
        local humanoidRootPart = character:WaitForChild("HumanoidRootPart")

        local originalPosition = humanoidRootPart.Position
        local originalAnchoredState = humanoidRootPart.Anchored

        humanoidRootPart.CFrame = CFrame.new(634.18, -4.00, 1839.65)
        wait(0.5)

        local args = { "PickingBoat", "MilitaryBoatFree" }
        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Ca1r"):FireServer(unpack(args))

        local function waitForBoatAndSit()
            local startTime = tick()
            while tick() - startTime < 10 do
                local vehicle = workspace.Vehicles:FindFirstChild(player.Name.."Car")
                if vehicle then
                    local vehicleSeat = vehicle:FindFirstChild("VehicleSeat") or vehicle:FindFirstChild("Seat") or vehicle:FindFirstChild("Body") and vehicle.Body:FindFirstChild("VehicleSeat")
                    if vehicleSeat then
                        humanoidRootPart.CFrame = vehicleSeat.CFrame * CFrame.new(0, 2, 0)
                        wait(0.2)
                        humanoid.Sit = true
                        firetouchinterest(humanoidRootPart, vehicleSeat, 0)
                        firetouchinterest(humanoidRootPart, vehicleSeat, 1)
                        wait(0.5)
                        if humanoid.SeatPart == vehicleSeat then
                            return true
                        end
                    end
                end
                wait(0.5)
            end
            warn("لم يتم العثور على السفينة أو المقعد خلال الوقت المحدد")
            return false
        end

        if waitForBoatAndSit() then
            local targetPlayer = Players:FindFirstChild(selectedBoatPlayer)
            if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                local targetPosition = targetPlayer.Character.HumanoidRootPart.Position
                local vehicle = workspace.Vehicles:FindFirstChild(player.Name.."Car")
                if vehicle then
                    vehicle:SetPrimaryPartCFrame(CFrame.new(targetPosition + Vector3.new(0, -2, 0)))
                    humanoidRootPart.CFrame = CFrame.new(targetPosition + Vector3.new(0, 5, 0))
                    local crazyStart = tick()
                    while tick() - crazyStart < 2 do
                        local offset = Vector3.new(math.random(-8,8), math.random(-3,1), math.random(-8,8))
                        vehicle:SetPrimaryPartCFrame(CFrame.new(targetPosition + Vector3.new(0, -2, 0) + offset))
                        wait(0.05)
                    end
                end
            end

            local targetDestination = Vector3.new(-86.00, -224.27, 34.57)
            local vehicle = workspace.Vehicles:FindFirstChild(player.Name.."Car")
            if vehicle then
                vehicle:SetPrimaryPartCFrame(CFrame.new(targetDestination))
                humanoidRootPart.CFrame = CFrame.new(targetDestination + Vector3.new(0, 5, 0))
                wait(0.5)
                vehicle:Destroy()
            end

            humanoidRootPart.CFrame = CFrame.new(originalPosition)
            humanoidRootPart.Anchored = originalAnchoredState
            humanoid:ChangeState(Enum.HumanoidStateType.RunningNoPhysics)
        end
    end
})

AddSection(Main, {"قـتـل بـالـبـاص"})

local selectedBusPlayer = nil

AddDropdown(Main, {
    Name = "اخـتـار الـلاعـب",
    Options = playerNames,
    Callback = function(selected)
        selectedBusPlayer = selected
    end
})

AddButton(Main, {
    Name = "اقـتـل الـلاعـب بـالـبـاص",
    Callback = function()
        if not selectedBusPlayer then
            print("لا يوجد لاعب محدد!")
            return
        end

        local player = Players.LocalPlayer
        local character = player.Character or player.CharacterAdded:Wait()
        local humanoidRootPart = character:WaitForChild("HumanoidRootPart")
        local originalPosition = humanoidRootPart.CFrame

        local function GetBus()
            local vehicles = workspace:FindFirstChild("Vehicles")
            if vehicles then
                return vehicles:FindFirstChild(player.Name.."Car")
            end
            return nil
        end

        local bus = GetBus()
        if not bus then
            humanoidRootPart.CFrame = CFrame.new(1118.81, 75.998, -1138.61)
            task.wait(0.5)
            local remoteEvent = game:GetService("ReplicatedStorage"):FindFirstChild("RE")
            if remoteEvent and remoteEvent:FindFirstChild("1Ca1r") then
                remoteEvent["1Ca1r"]:FireServer("PickingCar", "SchoolBus")
            end
            task.wait(1)
            bus = GetBus()
        end

        if bus then
            local seat = bus:FindFirstChild("Body") and bus.Body:FindFirstChild("VehicleSeat")
            if seat and character:FindFirstChildOfClass("Humanoid") and not character.Humanoid.Sit then
                repeat
                    humanoidRootPart.CFrame = seat.CFrame * CFrame.new(0, 2, 0)
                    task.wait()
                until character.Humanoid.Sit or not bus.Parent
            end
        end

        local destination = Vector3.new(265.46, -450.83, -59.93)
        spawn(function()
            while true do
                if selectedBusPlayer then
                    local targetPlayer = Players:FindFirstChild(selectedBusPlayer)
                    if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                        local targetHumanoid = targetPlayer.Character:FindFirstChildOfClass("Humanoid")
                        if targetHumanoid and targetHumanoid.Sit then
                            if character.Humanoid then
                                bus:SetPrimaryPartCFrame(CFrame.new(destination))
                                task.wait(0.2)
                                character.Humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
                                task.wait(0.5)
                                humanoidRootPart.CFrame = originalPosition
                            end
                            break
                        else
                            local targetRoot = targetPlayer.Character.HumanoidRootPart
                            local offset = math.sin(tick() * 32) * 8
                            bus:SetPrimaryPartCFrame(targetRoot.CFrame * CFrame.new(0, 0, -2) * CFrame.new(offset, 0, -2))
                        end
                    end
                end
                game:GetService("RunService").RenderStepped:Wait()
            end
        end)
    end
})
local Main = MakeTab({Name = "-تجسس-"})


-- Function to get all player names
local function getPlayerNames()
    local playerNames = {}
    for _, player in ipairs(game.Players:GetPlayers()) do
        table.insert(playerNames, player.Name)
    end
    return playerNames
end

-- Store selected player for later use
local selectedPlayer = nil
local followHead = false
local connection = nil

-- Function to spectate the selected player
local function spectatePlayer(enable)
    local player = game.Players.LocalPlayer
    local camera = workspace.CurrentCamera

    if selectedPlayer then
        local targetPlayer = game.Players:FindFirstChild(selectedPlayer)
        if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
            if enable then
                -- Set camera to follow the selected player
                camera.CameraSubject = targetPlayer.Character.Humanoid
            else
                -- Reset camera to default (back to the local player)
                camera.CameraSubject = player.Character.Humanoid
            end
        else
            print("Selected player not available or out of game.")
        end
    else
        print("No player selected!")
    end
end

-- Function to float just above the selected player's head without falling
local function floatAbovePlayerHead()
    local player = game.Players.LocalPlayer
    local character = player.Character or player.CharacterAdded:Wait()

    if character and character:FindFirstChild("HumanoidRootPart") then
        local humanoidRootPart = character.HumanoidRootPart

        if selectedPlayer then
            local targetPlayer = game.Players:FindFirstChild(selectedPlayer)

            if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("Head") then
                local targetHead = targetPlayer.Character.Head

                -- Position above the selected player's head
                humanoidRootPart.CFrame = targetHead.CFrame * CFrame.new(0, 3, 0)

                -- Keep updating the position every frame
                connection = game:GetService("RunService").Heartbeat:Connect(function()
                    if followHead and targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("Head") then
                        -- Update to stay above the player's head
                        humanoidRootPart.CFrame = targetPlayer.Character.Head.CFrame * CFrame.new(0, 3, 0)
                    else
                        connection:Disconnect() -- Disconnect if the toggle is off
                    end
                end)
            else
                print("Target player not found or not in the game.")
            end
        else
            print("No player selected!")
        end
    end
end

-- Function to trigger the secondary script
local function triggerCharacterSizeDown()
    local args = {
        [1] = "CharacterSizeDown",
        [2] = 2.4
    }
    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
end

-- Function to teleport behind the selected player and return after 1.5 seconds
local function moveBehindAndReturn()
    local player = game.Players.LocalPlayer
    local character = player.Character or player.CharacterAdded:Wait()
    local humanoidRootPart = character:FindFirstChild("HumanoidRootPart")

    if humanoidRootPart and selectedPlayer then
        local targetPlayer = game.Players:FindFirstChild(selectedPlayer)
        if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
            local targetHumanoidRootPart = targetPlayer.Character.HumanoidRootPart

            -- Store the original position
            local originalPosition = humanoidRootPart.CFrame

            -- Move behind the selected player
            humanoidRootPart.CFrame = targetHumanoidRootPart.CFrame * CFrame.new(0, 0, 3)

            -- Wait for 1.5 seconds before returning
            wait(1.5)

            -- Return to original position
            humanoidRootPart.CFrame = originalPosition
        else
            print("Selected player not found or not in the game.")
        end
    else
        print("No player or HumanoidRootPart found!")
    end
end

-- Create the dropdown with player names
AddDropdown(Main, {
    Name = "اخـتـار الـلاعـب",
    Default = "",
    Options = getPlayerNames(),
    Callback = function(value)
        selectedPlayer = value
        print("Player selected: " .. value)
    end
})


local flingToggle

-- Add a toggle that allows the player to spectate the selected player
AddToggle(Main, {
    Name = "شـاهـد الـلاعـب",
    Default = false,
    Callback = function(value)
        spectatePlayer(value)
    end
})

-- Add a button to teleport to the selected player
AddButton(Main, {
    Name = "الانـتـقـال الـى الـلاعـب",
    Callback = function()
        floatAbovePlayerHead()
    end
})


local Main = MakeTab({Name = "بـانـق"})


AddSection(Main, {"الـحمـايـة مـن الـجـلـوس"})


AddToggle(Main, {
    Name = "حـمـايـة جـلـوس",
    Default = false,
    Callback = function(state)
local seats = {}
for _, seat in next, workspace:GetDescendants() do
	if seat:IsA("Seat") then
		seats[seat] = true
	end
end

workspace.DescendantAdded:connect(function(seat)
	if seat:IsA("Seat") then
		seats[seat] = true
		seat.Disabled = not enabled
	end
end)

workspace.DescendantRemoving:connect(function(seat)
	if seat:IsA("Seat") then
		seats[seat] = nil
	end
end)

setEnabled = function(newEnabled)
	if newEnabled == enabled then
		return
	end
	enabled = newEnabled
	for seat, _ in next, seats do
		seat.Disabled = not enabled
	end
end

---

setEnabled(false)
	end,
})


AddSection(Main, {"الـحمـايـة مـن الـفـلـنـق"})


AddToggle(Main, {
    Name = "حـمـايـة فـلـنـق",
    Default = false,
    Callback = function(state)
		loadstring(game:HttpGet("https://raw.githubusercontent.com/NotAtomz/Atom-Scripts/refs/heads/main/anti%20fling"))()
	end,
})

AddSection(Main, {"الـكـنـبـة"})


AddButton(Main, {
  Name = "اضـغـط لاخـذ الـكـنـبة",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})


AddSection(Main, {"سـكربـت يـطـيـر اي شـخـص تـشـيلـه بـالـكـنـبـة"})

AddButton(Main, {
  Name = "سـكربـت قـتـل بـالـكـنبة",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe./main/Fling%20GUI"))()
  end
})


AddSection(Main, {"سـكربـت تـحـط اول  3 احـرف مـن الـي مـفـعـل عـلـيـك و يـمـوت"})


AddButton(Main, {
  Name = "سـكربـت يـقـتـل الـي يـفعـلون عـليـك",
  Callback = function()
    loadstring(game:HttpGet("https://scriptblox.com/raw/Universal-Script-FE-Fling-GUI-10927"))()
  end
})


AddSection(Main, {"سـكـربـت يـطـيـر الـي يـسـويـلـك bang او رحـمـة"})


AddButton(Main, {
  Name = "سـكربـت يـطـيـر الـي يـفعـلون عـليـك الـرحـمـة",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/zephyr10101/ignore-touchinterests/main/main",true))()
  end
})
local Main = MakeTab({Name = "سـكربـتـات صـمـلات"})


AddSection(Main, {"-سـكربـت ادمـن تـقـدر تـسوي فـيه اوامـر-"})


AddButton(Main, {
  Name = "سـكربـت ادمــن",
  Callback = function()
    loadstring(game:HttpGet('https://raw.githubusercontent.com/EdgeIY/infiniteyield/master/source'))()
  end
})


AddSection(Main, {"سـكربـت  تـخـريب و bang"})


AddButton(Main, {
  Name = "سـكربـت الـرحـمـة",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/n0kc/AtomicHub/main/Map-Al-Biout.lua"))()
  end
})


AddSection(Main, {"سـكـربـتـات تـحـمـيـك مـن الـخـروج"})



AddButton(Main, {
  Name = "سـكربـت AntiAFK 1",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/YallSumLs/Scripts/refs/heads/main/Anti-Afk"))()
  end
})


AddButton(Main, {
  Name = "سـكربـت AntiAFK 2",
  Callback = function()
 loadstring(game:HttpGet("https://raw.githubusercontent.com/hassanxzayn-lua/Anti-afk/main/antiafkbyhassanxzyn"))()
  end
})


AddButton(Main, {
  Name = "سـكربـت AntiAFK 3",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/ArgetnarYT/scripts/main/AntiAfk2.lua"))()
  end
})
local Main = MakeTab({Name = "سـبـام شـات"})


AddSection(Main, {"انـتـبـه مـن خـطـر الـبـانـد  ! "})


AddSection(Main, {"سبام سرعة 0.2"})

local TextSave
local tcs = game:GetService("TextChatService")
local chat = tcs.ChatInputBarConfiguration.TargetTextChannel
function sendchat(msg)
  if tcs.ChatVersion == Enum.ChatVersion.LegacyChatService then
    game:GetService("ReplicatedStorage"):FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg,"All")
  else
    chat:SendAsync(msg)
  end
end
AddTextBox(Main, {
  Name = "اكتب رسالتك",
  Description = "اكتب الرسالة",
  Flag = "هنا",
  Default = false,
  Callback = function(text)
    TextSave = text
  end
})



AddToggle(Main, {
  Name = "بدء السبام",
  Description = "سبام كتابتك",
  Flag = ".",
  Default = false,
  Callback = function(Value)
    getgenv().RaelHubSpawnText = Value
    while getgenv().RaelHubSpawnText do
      sendchat(TextSave)
      task.wait(0.2)
    end
  end
})

AddSection(Main, {"سبام سرعة 0.6"})
local TextSave
local tcs = game:GetService("TextChatService")
local chat = tcs.ChatInputBarConfiguration.TargetTextChannel
function sendchat(msg)
  if tcs.ChatVersion == Enum.ChatVersion.LegacyChatService then
    game:GetService("ReplicatedStorage"):FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg,"All")
  else
    chat:SendAsync(msg)
  end
end
AddTextBox(Main, {
  Name = "اكتب رسالتك",
  Description = "اكتب الرسالة",
  Flag = "هنا",
  Default = false,
  Callback = function(text)
    TextSave = text
  end
})



AddToggle(Main, {
  Name = "بدء السبام",
  Description = "سبام كتابتك",
  Flag = ".",
  Default = false,
  Callback = function(Value)
    getgenv().RaelHubSpawnText = Value
    while getgenv().RaelHubSpawnText do
      sendchat(TextSave)
      task.wait(0.6)
    end
  end
})
AddSection(Main, {"سبام سرعة 0.8"})

local TextSave
local tcs = game:GetService("TextChatService")
local chat = tcs.ChatInputBarConfiguration.TargetTextChannel
function sendchat(msg)
  if tcs.ChatVersion == Enum.ChatVersion.LegacyChatService then
    game:GetService("ReplicatedStorage"):FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg,"All")
  else
    chat:SendAsync(msg)
  end
end
AddTextBox(Main, {
  Name = "اكتب رسالتك",
  Description = "اكتب الرسالة",
  Flag = "هنا",
  Default = false,
  Callback = function(text)
    TextSave = text
  end
})



AddToggle(Main, {
  Name = "بدء السبام",
  Description = "سبام كتابتك",
  Flag = ".",
  Default = false,
  Callback = function(Value)
    getgenv().RaelHubSpawnText = Value
    while getgenv().RaelHubSpawnText do
      sendchat(TextSave)
      task.wait(0.8)
    end
  end
})
local TextSave
local tcs = game:GetService("TextChatService")
local chat = tcs.ChatInputBarConfiguration.TargetTextChannel
function sendchat(msg)
  if tcs.ChatVersion == Enum.ChatVersion.LegacyChatService then
    game:GetService("ReplicatedStorage"):FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg,"All")
  else
    chat:SendAsync(msg)
  end
end

AddSection(Main, {"سبام سرعة 1.0"})

local TextSave
local tcs = game:GetService("TextChatService")
local chat = tcs.ChatInputBarConfiguration.TargetTextChannel
function sendchat(msg)
  if tcs.ChatVersion == Enum.ChatVersion.LegacyChatService then
    game:GetService("ReplicatedStorage"):FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg,"All")
  else
    chat:SendAsync(msg)
  end
end
AddTextBox(Main, {
  Name = "اكتب رسالتك",
  Description = "اكتب الرسالة",
  Flag = "هنا",
  Default = false,
  Callback = function(text)
    TextSave = text
  end
})
AddToggle(Main, {
  Name = "بدء السبام",
  Description = "سبام كتابتك",
  Flag = ".",
  Default = false,
  Callback = function(Value)
    getgenv().RaelHubSpawnText = Value
    while getgenv().RaelHubSpawnText do
      sendchat(TextSave)
      task.wait(1.0)
    end
  end
})
local Main = MakeTab({Name = "اغـانـي الـفـونـك"})

local section = AddSection(Main, {"ادخـل كـود الاغـنـيـة"})

AddTextBox(Main, {
  Name = "ادخـل الـكـود",
  Default = "",
  PlaceholderText = "هـنـا",
  ClearText = true,
  Callback = function(Value)
local args1 = {
            [1] = "SkateBoard"
        }
        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1NoMoto1rVehicle1s"):FireServer(unpack(args1))

        -- Replacing the static value with the input from the textbox
        local args2 = {
            [1] = "PickingScooterMusicText",
            [2] = Value -- Here, we use the textbox value to replace 35935204
        }
        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1NoMoto1rVehicle1s"):FireServer(unpack(args2))

end
})

AddSection(Main, {"فــونـك"})

AddButton(Main, {
  Name = "افـخـم فـونـك",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "17647322226"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



AddButton(Main, {
  Name = "فـونـك غـضـب",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "115859025716354"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



AddButton(Main, {
  Name = "فـونـك 5×30",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "73966367524216"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك عالـمي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "76578817848504"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك تـيك تـوك",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "93218265275853"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



AddButton(Main, {
  Name = "فـونـك مـمتاز",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "102402883551679"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "فـونـك روسـي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "103066073385622"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك بـرازيـل",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "75038862482887"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك هـنـدي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "91301048841024"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك جـهـنـمي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "96527800313172"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "فـونـك اسـطوري",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "115028690484951"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



AddButton(Main, {
  Name = "فـونـك الـتربيـة السيـئة",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "91161894069716"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddSection(Main, {"اغـانـي مـشـهـورة"})


AddButton(Main, {
  Name = "اغـنيـة xxxtentacion",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "105663787518318"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اغـنيـة امـنـيـم",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "1841374584"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اغـنيـة مـشـهورة 1",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "76463442516219"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اغـنيـة مـشـهورة 2",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "1846687233"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اغـنيـة مـشـهورة 3",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "72515474996038"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



local Main = MakeTab({Name = "اغـانـي عربـية"})

local section = AddSection(Main, {"ادخـل كـود الاغـنـيـة"})

AddTextBox(Main, {
  Name = "ادخـل الـكـود",
  Default = "",
  PlaceholderText = "هـنـا",
  ClearText = true,
  Callback = function(Value)
local args1 = {
            [1] = "SkateBoard"
        }
        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1NoMoto1rVehicle1s"):FireServer(unpack(args1))

        -- Replacing the static value with the input from the textbox
        local args2 = {
            [1] = "PickingScooterMusicText",
            [2] = Value -- Here, we use the textbox value to replace 35935204
        }
        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1NoMoto1rVehicle1s"):FireServer(unpack(args2))

end
})

AddSection(Main, {"عـراقـي"})

AddButton(Main, {
  Name = "يا حتـه من كـلبي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "119630965566559"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "عـفـت كـلبـي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "131004009162099"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "مـا نـريـدك",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "80039364766636"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "الـعراقـي لـو نـزل",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "111256095783364"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "كـل عقـلك تحـجي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "122774951440401"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "مـا اريـدك تـهوانـي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "135911328646170"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "جـاي انـسـاك",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "72918998227337"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "نـجـوم الـدنـيه",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "73632319736202"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddSection(Main, {"اغـانـي عربـيـة"})


AddButton(Main, {
  Name = "لـيـه ساكـت",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "119437864395329"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اا يـاحـلو",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "93620598835551"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})



AddButton(Main, {
  Name = "يـا بـكايـة",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "98640789490482"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "صدقـني كـرهـتك",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "113478978326245"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "انـا دمـي فلـسطيـني",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "84112690044490"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "كـردي",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "134738554464984"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "اغـنيـة هـجـولـة",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "99472699182002"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "تـحـريـر سـوريـا",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "87510423075068"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "دبـكـة 1",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "76698985299412"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "دبـكـة 2",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "90807238125839"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddSection(Main, {"قـرأن"})


AddButton(Main, {
  Name = "هـل لـك سـر عنـد الله",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "89807249526206"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "قـرأن 1",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "1836685929"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "قـرأن 2",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "113184639716766"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "قـرأن 3",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "113267251759253"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "قـرأن 4",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "104251523505775"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "قـرأن 5",
  Callback = function()
    	local args = {
    [1] = "SkateBoard"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
local args = {
    [1] = "PickingScooterMusicText",
    [2] = "94610377976036"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1NoMoto1rVehicle1s"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "الـرؤوس و الارجـل"})

AddButton(Main, {
  Name = "رأس روبـوت",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 3210773801;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رأس بـنـت كـيـوت",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 140991;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رأس مـخـفـي",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 134082579;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رأس كـوبـي | رول",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 746767604;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "رأس عـيـون زرقـاء",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 16580493236;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddSection(Main, {"الارجـل"})


AddButton(Main, {
    Name = "رجـل مـقـطـوعـة لـلـبـنـات",
    Callback = function()
        local args = {
            [1] = {
                [1] = 96491916349570;
                [2] = 76683091425509;
                [3] = 75159926897589;
                [4] = 139607718;
                [5] = 1;
                [6] = 1;
            };
        }
        game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))
    end
})



AddButton(Main, {
  Name = "رجـل مـقـطـوعـة لـلـولـد",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 1;
        [2] = 1;
        [3] = 1;
        [4] = 139607718;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "رجـل حـديـديـة",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 1;
        [2] = 1;
        [3] = 1;
        [4] = 17500249989;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "رجـل الـعـضـم الـرصـاصـي",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 1;
        [2] = 1;
        [3] = 1;
        [4] = 14547162578;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "رجـل رول",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 1;
        [2] = 1;
        [3] = 1;
        [4] = 3230472745;
        [5] = 3230470862;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})
local Main = MakeTab({Name = "الاجـسـام"})


AddSection(Main, {"اجـسـام الـبـنـات"})


AddButton(Main, {
  Name = "جـسـم بـنـت 1",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 96491916349570;
        [2] = 76683091425509;
        [3] = 75159926897589;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم بـنـت 2",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 74302534603111;
        [2] = 76683091425509;
        [3] = 75159926897589;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 3",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 124754866635882;
        [2] = 76683091425509;
        [3] = 75159926897589;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 4",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 96491916349570;
        [2] = 14854350570;
        [3] = 14854350451;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 5",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 101577365085156;
        [2] = 121017849910260;
        [3] = 111571034664628;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 6",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 18839824113;
        [2] = 18839824209;
        [3] = 18839824132;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 7",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 16214246112;
        [2] = 76683091425509;
        [3] = 16214251181;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 8",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 15539008532;
        [2] = 15539008875;
        [3] = 15539008680;
        [4] = 15539008795;
        [5] = 15539011945;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})

AddButton(Main, {
  Name = "جـسـم بـنـت 9",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 14861800638;
        [2] = 14861800626;
        [3] = 14861801452;
        [4] = 14861800627;
        [5] = 14861801454;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddSection(Main, {"اجـسـام الـولـد"})

AddButton(Main, {
  Name = "جـسـم ولـد 1",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 17754346388;
        [2] = 1;
        [3] = 1;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم ولـد 2",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 92757812011061;
        [2] = 99519402284266;
        [3] = 115905570886697;
        [4] = 1;
        [5] = 1;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم ولـد كـوبـي",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 86499666;
        [2] = 27112039;
        [3] = 27112052;
        [4] = 27112068;
        [5] = 27112056;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم ولـد رول",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 27112025;
        [2] = 27112039;
        [3] = 27112052;
        [4] = 3230472745;
        [5] = 3230470862;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم ولـد مـعـضـل",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 18178775358;
        [2] = 18178775182;
        [3] = 18178775725;
        [4] = 18178777453;
        [5] = 18178775695;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})



AddSection(Main, {"اجـسـام الـقـزم"})


AddButton(Main, {
  Name = "جـسـم قـزم",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 14579958702;
        [2] = 14579959062;
        [3] = 14579959191;
        [4] = 14579959249;
        [5] = 14579963667;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم قـزم مـتـوسـط",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 77813057823038;
        [2] = 135110043370135;
        [3] = 116607813654019;
        [4] = 138966229804486;
        [5] = 128961183894053;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم قـزم صـغـيـر",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 120973199097564;
        [2] = 118345433416023;
        [3] = 112849465115864;
        [4] = 78321005147549;
        [5] = 106586789635639;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم قـزم الـمـربـع",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 126267841602936;
        [2] = 77530451194918;
        [3] = 123471958406889;
        [4] = 117042768644173;
        [5] = 131948590344338;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})


AddButton(Main, {
  Name = "جـسـم قـزم بـنـت",
  Callback = function()
print("Clicked")local args = {
    [1] = {
        [1] = 15282063616;
        [2] = 15282063632;
        [3] = 15282063615;
        [4] = 14538400463;
        [5] = 14538400387;
        [6] = 1;
    };
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("ChangeCharacterBody", 9e9):InvokeServer(unpack(args))

end
})
local Main = MakeTab({Name = "اكـواد مـلابـس"})


AddSection(Main, {"اكـمام الـيد"})


AddButton(Main, {
  Name = "قـفازات يد اسود مخطط",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 9239689111;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "سـتـرة اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 89892588488089;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "سـتـرة زهـري كـيـوت ",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 99429391843259;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})


AddButton(Main, {
  Name = "قـفازات يد اسود عـادي 1",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 10789914680;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد اسود عـادي 2",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11363898043;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد اسود عـادي 3",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 10791180072;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد ابـيـض مزخرف ",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 10871965173;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد زهري",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 10789939838;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد احـمـر",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12379676852;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "اضـافـر اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12825022709;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})


AddButton(Main, {
  Name = "قـفازات يد قـصـير 1",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12483105503;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد قـصـير 2",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12483109504;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})


AddButton(Main, {
  Name = "قـفازات يد قـصـير 3",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11613796964;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد قـصـير 4",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 10954568687;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد قـصـير 5",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11679250718;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "قـفازات يد قـصـير 6",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11182924874;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddSection(Main, {"اكـمام الرجـل"})

AddButton(Main, {
  Name = "حـذاء الـشيطـان زهري",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14388006902;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء الـشيطـان احـمـر",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14388019333;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء الـشيطـان ابـيض",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14387999337;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء الـشيطـان اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14388004031;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء طـويل اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11433864064;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء طـويل ابـيض",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11111279400;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء طـويل ابـيض و احـمر",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11708887517;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء الـقـرش الاسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13463375063;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 1",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 11856087406;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 2",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14388001192;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 3",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12453321203;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 4",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338742287;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 5",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338742287;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 6",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12296189693;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 7",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338732820;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 8",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338735628;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 9",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338738380;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "حـذاء قـصـير 10",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 14338744418;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})


AddSection(Main, {"اشـياء للـيـد"})

AddButton(Main, {
  Name = "ورد اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12465465333;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "ورد ابـيض",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12465472210;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "ورد احـمـر",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12465376206;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "ورد احـمـر و ابـيض",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 1246535644;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "ورد زهـري",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 1246547853;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "ورد سـمـائـي",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12465483807;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "دب ابـيض",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12156704614;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "دب ابـيض و اسـود",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 12157590166;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "مسـدس مـاء لعـبة",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13135818072;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddSection(Main, {"الاشـواك"})

AddButton(Main, {
  Name = "شـوك 1",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13463287248;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "شـوك 2",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 3463272877;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "شـوك 3",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13463272877;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "شـوك 4",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13463355223;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "شـوك 5",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 3463292395;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "شـوك 6",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 13463290106;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddSection(Main, {"مـلابـس كـيـوت "})

AddButton(Main, {
  Name = "لـبـس كـيـوت 1",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 84110484978046;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "لـبـس كـيـوت 2",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 75698084918608;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "لـبـس كـيـوت 3",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 79220663432789;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "لـبـس كـيـوت 4",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 78061398976556;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})

AddButton(Main, {
  Name = "لـبـس كـيـوت 5",
  Callback = function()
  wait(0.1)
  local args = {
    [1] = 93303265717630;
}

game:GetService("ReplicatedStorage"):WaitForChild("Remotes", 9e9):WaitForChild("Wear", 9e9):InvokeServer(unpack(args))
end
})
local Main = MakeTab({Name = "الاسـمـاء"})


AddSection(Main, {"الاسـم"})


AddTextBox(Main, {
Name = "ضـع اسـم",
Default = "",
PlaceholderText = "",
ClearText = true,
Callback = function(value)
local args = {[1] = "RolePlayName", [2] = value};
        game:GetService("ReplicatedStorage").RE:FindFirstChild(
            "1RPNam1eTex1t"):FireServer(unpack(args));
    end
})

-- Variáveis para rastrear os estados dos toggles
local isNameActive = false
local isBioActive = false

-- Toggle para ativar/desativar o RGB Name
Toggle = AddToggle(Main, {
Name = "تـلـويـن الاسم",
Default = false,
Callback = function(value)
isNameActive = value -- Define o estado baseado no toggle
        if isNameActive then
            print("RGB Name ativado")
        else
            print("RGB Name desativado")
        end
    end
})

AddSection(Main, {"الـبـايـو"})

AddTextBox(Main, {
Name = "ضـع الـبـايـو",
Default = "",
PlaceholderText = "",
ClearText = true,
Callback = function(value)
     local args = {[1] = "RolePlayBio", [2] = value};
        game:GetService("ReplicatedStorage").RE:FindFirstChild(
            "1RPNam1eTex1t"):FireServer(unpack(args));
    end
})

-- Toggle para ativar/desativar o RGB BIO
Toggle = AddToggle(Main, {
Name = "تـلـويـن الـبـايو",
Default = false,
Callback = function(value)
isBioActive = value -- Define o estado baseado no toggle
        if isBioActive then
            print("RGB BIO ativado")
        else
            print("RGB BIO desativado")
        end
    end
})

-- Thread separada para o RGB Name
spawn(function()
    local vibrantColors = {
        Color3.fromRGB(255, 0, 0),   -- Vermelho
        Color3.fromRGB(0, 255, 0),   -- Verde
        Color3.fromRGB(0, 0, 255),   -- Azul
        Color3.fromRGB(255, 255, 0), -- Amarelo
        Color3.fromRGB(255, 0, 255), -- Magenta
        Color3.fromRGB(0, 255, 255), -- Ciano
        Color3.fromRGB(255, 165, 0), -- Laranja
        Color3.fromRGB(128, 0, 128), -- Roxo
        Color3.fromRGB(255, 20, 147) -- Rosa choque
    }

    while true do
        if isNameActive then
            local randomColor = vibrantColors[math.random(#vibrantColors)]
            local args = {
                [1] = "PickingRPNameColor",
                [2] = randomColor
            }
            game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eColo1r"):FireServer(unpack(args))
        end
        wait(0.7) -- Ajuste o tempo de espera conforme necessário
    end
end)

-- Thread separada para o RGB BIO
spawn(function()
    local vibrantColors = {
        Color3.fromRGB(255, 0, 0),   -- Vermelho
        Color3.fromRGB(0, 255, 0),   -- Verde
        Color3.fromRGB(0, 0, 255),   -- Azul
        Color3.fromRGB(255, 255, 0), -- Amarelo
        Color3.fromRGB(255, 0, 255), -- Magenta
        Color3.fromRGB(0, 255, 255), -- Ciano
        Color3.fromRGB(255, 165, 0), -- Laranja
        Color3.fromRGB(128, 0, 128), -- Roxo
        Color3.fromRGB(255, 20, 147) -- Rosa choque
    }

    while true do
        if isBioActive then
            local randomColor = vibrantColors[math.random(#vibrantColors)]
            local args = {
                [1] = "PickingRPBioColor",
                [2] = randomColor
            }
            game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eColo1r"):FireServer(unpack(args))
        end
        wait(0.7) -- Ajuste o tempo de espera conforme necessário
    end
end)


AddSection(Main, {"-الاسـمـاء الـجـاهـزة-"})


AddButton(Main, {
  Name = "نور",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "نٌـّوٌَر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "منه",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـِنـهه"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "لارا",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "لآرآ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "روز",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رِوزِ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رزان",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رِزٰآنَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "مارتن",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مـٓارِتـن"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "فضل",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "فَــضُـل"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "عمر",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عـمر"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ريتاج",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رِيـتـّاجُ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "ريحانه",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ريـحـِاُنـه"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "بطيخه",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "بـُطـيـخـه"
}
game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "امنه",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "امـنـَهه"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "زينب",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "زّيـِنب"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "رجب",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "رجــب"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "جكليته",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "جـكـلـيـتهه"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "احمد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "احــمـد"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "ايه",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "أيهَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "زهراء",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "زهـرَاّءٰ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "ايات",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ايُـّاًّتَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "شهد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "شُهّدٍ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "علي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عّـلُـي"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "مجتبى",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مجتـَبىً"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "ياسين",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "ياسَيـَنّ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "اثيرَ",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "اثّيـرَ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "عبسي",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عبَـّسيّ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "عبدالله",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "عىٕدَالُلهّ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})


AddButton(Main, {
  Name = "محمد",
  Callback = function()
    local args = {
    [1] = "RolePlayName",
    [2] = "مَـٓحمًدٓ"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
  end
})
local Main = MakeTab({Name = "قـيـم بـاسـات"})


local section = AddSection(Main, {"مـلاحـضـة :  الـقـيم بـاسـات مـو حقـيقيـة يعـني تضـهـر بـس عـنـدك  ! "})


AddButton(Main, {
  Name = "VIP مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.VIP.Value = true
  end
})


AddButton(Main, {
  Name = "نـجـمـة مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.SilverPass.Value = true
  end
})


AddButton(Main, {
  Name = "سـرعـة مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.SpeedPass200.Value = true
  end
})


AddButton(Main, {
  Name = "اغـانـي مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.MusicPass.Value = true
  end
})


AddButton(Main, {
  Name = "الاحـصـنـة مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.HorsePass.Value = true
  end
})


AddButton(Main, {
  Name = "قـفـل سيـارات مجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.VehiclePackPass.Value = true
  end
})


AddButton(Main, {
  Name = "قـصـر مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.MansionPass.Value = true
  end
})


AddButton(Main, {
  Name = "وجـه مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.FacePass.Value = true
  end
})


AddButton(Main, {
  Name = "تـكـسير الـبـيت مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.DisasterPass.Value = true
  end
})


AddButton(Main, {
  Name = "الـسـفـيـنة مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.BoatPass.Value = true
  end
})


AddButton(Main, {
  Name = "اراضـي مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.PenthousePass.Value = true
  end
})


AddButton(Main, {
  Name = "نـار مـجـانـي",
  Callback = function()
 game:GetService("Players").LocalPlayer.PlayersBag.FirePass.Value = true
  end
})
local Main = MakeTab({Name = "الـكـشـف"})
local ESP = loadstring(game:HttpGet("https://kiriot22.com/releases/ESP.lua"))()
ESP:Toggle(true)
ESP.Players = false
ESP.Names = false

local Toggle = AddToggle(Main, {
  Name = "تـفـعـيـل الـكـشـف",
  Default = false,
  Callback = function(Value)
    ESP.Players = Value
  end
})

local Toggle = AddToggle(Main, {
  Name = "كـشـف اسـامـي الـلاعـبـيـن",
  Default = false,
  Callback = function(Value)
    ESP.Names = Value
  end
})
AddColorPicker(Main, {
  Name = "لـون الـكـشـف",
  Default = Color3.fromRGB(255, 255, 0),
  Callback = function(Value)
    ESP.Color = Value
  end
})
local Main = MakeTab({Name ="اوامـر الـلاعـب"})

AddTextBox(Main, {
  Name = "الـسـرعـة",
  Default = "",
  PlaceholderText = "ادخـل الـرقـم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = value
 end
})
AddTextBox(Main, {
  Name = "الـقـفـز",
  Default = "",
  PlaceholderText = "ادخـل الـرقـم",
  ClearText = true,
  Callback = function(value)
game.Players.LocalPlayer.Character.Humanoid.JumpPower = value
  end
})
AddTextBox(Main, {
  Name = "الـشـاشـة Fov",
  Default = "",
  PlaceholderText = "ادخـل الـرقـم",
  ClearText = true,
  Callback = function(value)
local FovNumber = value
local Camera = workspace.CurrentCamera
Camera.FieldOfView = FovNumber
  end
})
AddTextBox(Main, {
  Name = "الـدوران spin",
  Default = "",
  PlaceholderText = "ادخـل الـرقـم",
  ClearText = true,
  Callback = function(Value)
    getgenv().Spinspeed = Value

local Spin = Instance.new'BodyAngularVelocity'
Spin.Parent = game:GetService'Players'.LocalPlayer.Character:FindFirstChild'HumanoidRootPart'
Spin.MaxTorque = Vector3.new(0, math.huge, 100)
wait(0.1)
Spin.AngularVelocity = Vector3.new(100,Spinspeed,0)
  end
})

function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end

-- Variáveis e funções para a visualização dos jogadores
local viewEnabled = false
local selectedViewPlayer = nil
local characterAddedConnection = nil

local function toggleView(enabled)
    if enabled then
        if selectedViewPlayer then
            local player = selectedViewPlayer
            if player then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
                if characterAddedConnection then
                    characterAddedConnection:Disconnect()
                end
                characterAddedConnection = player.CharacterAdded:Connect(function(character)
                    game.Workspace.CurrentCamera.CameraSubject = character
                end)
                MakeNotifi({
                    Title = "Visualizando " .. player.Name,
                    Text = "Você está visualizando o jogador: " .. player.Name,
                    Time = 6
                })
            else
                print("Jogador não encontrado.")
                viewEnabled = false
            end
        else
            print("Nenhum jogador selecionado para a visualização.")
            viewEnabled = false
        end
    else
        if characterAddedConnection then
            characterAddedConnection:Disconnect()
            characterAddedConnection = nil
        end
        game.Workspace.CurrentCamera.CameraSubject = game.Players.LocalPlayer.Character
    end
end

local value = "" -- Variável para armazenar o nome digitado

local function findPlayerByPartialNameOrNickname(partialName)
    value = partialName -- Atualiza a variável com o nome digitado completo
    for _, player in ipairs(game.Players:GetPlayers()) do
        if player.Name:lower():find(partialName:lower(), 1, true) or (player.DisplayName and player.DisplayName:lower():find(partialName:lower(), 1, true)) then
            return player
        end
    end
    return nil
end


-- Conectando eventos de jogador removido
game.Players.PlayerRemoving:Connect(function(player)
    if selectedViewPlayer == player then
        selectedViewPlayer = nil
        if viewEnabled then
            toggleView(false)
            MakeNotifi({
                Title = "Jogador Saiu",
                Text = player.Name .. " saiu do jogo. Visualização desativada.",
                Time = 5
            })
        end
    end
end)

-- Função para manter a câmera no jogador selecionado
local function maintainView()
    while wait() do
        if viewEnabled and selectedViewPlayer then
            local player = selectedViewPlayer
            if player and game.Workspace.CurrentCamera.CameraSubject ~= player.Character then
                game.Workspace.CurrentCamera.CameraSubject = player.Character
            end
        end
    end
end


-- Variável para controlar o estado do Noclip
local noclipEnabled = false
local runService = game:GetService("RunService")

-- Função para definir CanCollide para todas as partes do personagem
local function setCharacterCanCollide(character, canCollide)
    for _, part in ipairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.CanCollide = canCollide
        end
    end
end

-- Função de callback para o botão de alternância de Noclip
local function onNoclipToggle(value)
    noclipEnabled = value
    print("Noclip Enabled:", noclipEnabled)

    local player = game.Players.LocalPlayer
    local character = player.Character

    if noclipEnabled then
        -- Inicia um loop para continuamente definir CanCollide
        noclipLoop = runService.Stepped:Connect(function()
            if character then
                setCharacterCanCollide(character, false)
            end
        end)
    else
        -- Desativa o loop e restaura CanCollide
        if noclipLoop then
            noclipLoop:Disconnect()
        end
        if character then
            setCharacterCanCollide(character, true)
        end
    end
end

-- Adiciona o botão de alternância "Noclip"
local Toggle = AddToggle(Main, {
    Name = "اخـتـراق الحـائط",
    Default = false,
    Callback = onNoclipToggle
})
`
            },
        {
          id: "zxe hub",
                name: "غالي",
                type: "txt",
                size: "64KB",
                description: "سكربت غالي تحت الصيانه البحث  : zxe hub",
                downloads: "8",
                category: "غالي",
                content:`local args = {
  [1] = "RolePlayName",
  [2] = "ghali HUB | Bate V.1 "
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))

wait(0.1)
local args = {
  [1] = "RolePlayBio",
  [2] = "مطور السكربت غالي "
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
wait(0.1)

game.StarterGui:SetCore("SendNotification", {
  Title = "ghali hub";
  Text = " اذا واجهت اي مشكلة  في النط اقتل نفسك";
  Icon = "rbxassetid://1746049731918";
  Duration = 5;
})

game.StarterGui:SetCore("SendNotification", {
  Title = "اهلا بكم";
  Text = " السكربت لسا تجريبي";
  Icon = "rbxassetid://1746049731918";
  Duration = 5;
})

loadstring(game:HttpGet(("https://raw.githubusercontent.com/speedwave1/speed_wave/refs/heads/main/i2att")))()
MakeWindow({
    Hub = {
      Title = "ghali Bate | Brookhaven | سكربت جديد",
      Animation = "gghali33يرحب بك "
    },
    Key = {
      KeySystem = false,
      Title = "Key System",
      Description = "",
      KeyLink = "",
      Keys = {"1234"},
      Notifi = {
        Notifications = true,
        CorrectKey = "Running the Script...",
        Incorrectkey = "The key is incorrect",
        CopyKeyLink = "Copied to Clipboard"
      }
    }
  })
  MinimizeButton({
    Image = "rbxassetid://1746049731918",
    Size = {50,50},
    Color = Color3.fromRGB(10, 10, 10),
    Corner = true,
    Stroke = false,
    StrokeColor = Color3.fromRGB(0, 0, 0),
  })


local Main = MakeTab({Name = "الحقوق"})
local Image = AddImageLabel(Main, {
  Name = "اهلا بكم",
  Image = "rbxassetid://1746049731918"
})
local section  = AddSection(Main, {"حسابات المطور | اي سؤال | اي فكره | اي تحديث | ادخل قناتي"})


AddButton(Main, {
  Name = " انسخ حسابي تيك ",
  Callback = function()
    game.StarterGui:SetCore("SendNotification", {
        Title = "تم النسخ";
        Text = " تم نسخ الاسم في الحافظه"; -- ARAB TEAM
        Duration = 5;
    })

    setclipboard('gghali33')
  end
})

AddButton(Main, {
    Name = "انسخ حسابي روب",
    Callback = function()
        game.StarterGui:SetCore("SendNotification", {
            Title = "تم النسخ";
            Text = " تم نسخ الاسم في الحافظه"; -- ARAB TEAM
            Duration = 5;
        })

      setclipboard('ghali0059')
    end
  })

  AddButton(Main, {
    Name = "انسخ حساب خالد",
    Callback = function()
        game.StarterGui:SetCore("SendNotification", {
            Title = "تم النسخ";
            Text = " تم نسخ الاسم في الحافظه"; -- ARAB TEAM
            Duration = 5;
        })

      setclipboard('5ze_1')
    end
  })

local Main = MakeTab({Name = "حماية"})
local section = AddSection(Main, {"قريبا. . ."})

  local Main = MakeTab({Name = "السكربتات"})
  AddButton(Main, {
    Name = "سكربت جودة  ",
    Callback = function()
      loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-Rtx-graphics-25102"))()
    end
  })

  AddButton(Main, {
    Name = "سكربت رقصات ",
    Callback = function()
      loadstring(game:HttpGet("https://raw.githubusercontent.com/S2EXE/GUI12-/refs/heads/main/SaifloveU"))()
    end
  })

  AddButton(Main, {
    Name = "مشيات ",
    Callback = function()
      loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-AFEM-14048"))()
    end
  })

  AddButton(Main, {
    Name = "سكربت نسخ سكنـات ",
    Callback = function()
      loadstring(game:HttpGet("https://rawscripts.net/raw/Universal-Script-rochips-universal-18294"))()
    end
  })

  AddButton(Main, {
    Name = "سكربت الهلال ",
    Callback = function()
      loadstring(game:HttpGet("https://raw.githubusercontent.com/n0kc/AtomicHub/main/Map-Al-Biout.lua"))()
    end
  })

  AddButton(Main, {
    Name = "سكربت اختفاء ",
    Callback = function()
      loadstring(game:HttpGet('https://pastebin.com/raw/3Rnd9rHf'))()
    end
  })

  AddButton(Main, {
    Name = " سكربت طيران كنبة  ",
    Callback = function()
      loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe./main/Fling%20GUI"))()
    end
  })

  AddButton(Main, {
    Name = " سكربت طيران  ",
    Callback = function()
      loadstring(game:HttpGet("https://raw.githubusercontent.com/S2EXE/hi/refs/heads/main/fly%20gui%20freee"))()
    end
  })

  AddButton(Main, {
    Name = " سكربـت اغاني  ",
    Callback = function()
      loadstring(game:HttpGet('https://raw.githubusercontent.com/M1ZZ001/BrookhavenR4D/main/Brookhaven%20R4D%20Script'))()
    end
  })

  AddButton(Main, {
    Name = "سكربت قفل",
    Callback = function()
      loadstring(game:HttpGet("https://raw.githubusercontent.com/Sector9922/SECTOR-SHIFT-LOCK/main/SECTOR%20SHIFT%20LOCK"))()
    end
  })

local Main = MakeTab({Name = "الاعب"})

local section = AddSection(Main, {"تقدر تحكم في لاعبك"})

AddButton(Main, {
  Name = " V1 سكربت طيران",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/S2EXE/hi/refs/heads/main/fly%20gui%20freee"))()
  end
})

AddTextBox(Main, {
    Name = "سرعة ",
    Default = "",
    PlaceholderText = "هــنــا",
    ClearText = true,
    Callback = function(value)
  game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = value
   end
  })
  AddTextBox(Main, {
    Name = "قفز ",
    Default = "",
    PlaceholderText = "هــنــا",
    ClearText = true,
    Callback = function(value)
  game.Players.LocalPlayer.Character.Humanoid.JumpPower = value
    end
  })
  AddTextBox(Main, {
    Name = "ابعاد الشاشه",
    Default = "",
    PlaceholderText = "هــنــا",
    ClearText = true,
    Callback = function(value)
  local FovNumber = value
  local Camera = workspace.CurrentCamera
  Camera.FieldOfView = FovNumber
    end
  })
  AddTextBox(Main, {
    Name = " دوران",
    Default = "",
    PlaceholderText = "هــنــا",
    ClearText = true,
    Callback = function(Value)
      getgenv().Spinspeed = Value

  local Spin = Instance.new'BodyAngularVelocity'
  Spin.Parent = game:GetService'Players'.LocalPlayer.Character:FindFirstChild'HumanoidRootPart'
  Spin.MaxTorque = Vector3.new(0, math.huge, 100)
  wait(0.1)
  Spin.AngularVelocity = Vector3.new(100,Spinspeed,0)
    end
  })


AddButton(Main, {
  Name = "امر تعليق السيرفر",
  Callback = function()
tools = "FireX"
        shutdownserver = true
        if game.Players.LocalPlayer.Character.Humanoid.Sit == true then
            task.wait()
            game.Players.LocalPlayer.Character.Humanoid.Sit = false
        end
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        wait(0.1)
        if game:GetService("Workspace"):FindFirstChild("Camera") then
            game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
        end
        game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.CFrame + Vector3.new(0, -15, 0)
        task.wait(0.2)
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = true
        ddos = true
        for i = 1, 1350 do
            task.wait()
            if ddos == false then
                local args = {
                    [1] = "ClearAllTools"
                }

                cleartoolremote:FireServer(unpack(args))
                game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
                game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(9999, -475, 9999)
                return
            end
            if game:GetService("Workspace"):FindFirstChild("Camera") then
                game:GetService("Workspace"):FindFirstChild("Camera"):Destroy()
            end
            if game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools) then
                game:GetService("Players").LocalPlayer.Character:FindFirstChild(tools):Destroy()
            end
            if ddos == false then return end
            fireclickdetector(game:GetService("Workspace").WorkspaceCom["001_GiveTools"].FireX.ClickDetector, 0)
        end
        game.Players.LocalPlayer.Character.HumanoidRootPart.Anchored = false
        game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, -475, 0)
  end
})
AddButton(Main, {
  Name = "طرد الكل ",
  Callback = function()
    local player = game.Players.LocalPlayer
        player:Kick("مصدق يطرد الكل؟")
  end
})
AddButton(Main, {
  Name = "امر تدمير العالم",
  Callback = function()
    game.Workspace:ClearAllChildren()
  end
})

local infiniteJumpEnabled = false

-- Conectar o evento de pulo somente uma vez
local infiniteJumpConnection

-- Função de callback para o botão de alternância de pulo infinito
local function onInfiniteJumpToggle(value)
    infiniteJumpEnabled = value
    print("Infinite Jump Enabled:", infiniteJumpEnabled)

    -- Conectar o evento de pulo somente uma vez
    if not infiniteJumpConnection then
        infiniteJumpConnection = game:GetService("UserInputService").JumpRequest:Connect(function()
            if infiniteJumpEnabled then
                local player = game.Players.LocalPlayer
                local character = player.Character
                if character and character:FindFirstChildOfClass("Humanoid") then
                    character:FindFirstChildOfClass("Humanoid"):ChangeState("Jumping")
                end
            end
        end)
    end
end

-- Adiciona o botão de alternância "Infinitejump"
local Toggle = AddToggle(Main, {
    Name = "قفز لا نهائي ",
    Default = false,
    Callback = onInfiniteJumpToggle
})
function MakeNotifi(notification)
    game.StarterGui:SetCore("SendNotification", {
        Title = notification.Title;
        Text = notification.Text;
        Duration = notification.Time;
    })
end

AddButton(Main, {
  Name = "اختفاء اللاعب",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 6
}
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "إلغاء اختفاء",
  Callback = function()
    local args = {
    [1] = "CharacterSizeUp",
    [2] = 1
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clothe1s"):FireServer(unpack(args))
  end
})
-- Variável para controlar o estado do Noclip
local noclipEnabled = false
local runService = game:GetService("RunService")

-- Função para definir CanCollide para todas as partes do personagem
local function setCharacterCanCollide(character, canCollide)
    for _, part in ipairs(character:GetDescendants()) do
        if part:IsA("BasePart") then
            part.CanCollide = canCollide
        end
    end
end

-- Função de callback para o botão de alternância de Noclip
local function onNoclipToggle(value)
    noclipEnabled = value
    print("Noclip Enabled:", noclipEnabled)

    local player = game.Players.LocalPlayer
    local character = player.Character

    if noclipEnabled then
        -- Inicia um loop para continuamente definir CanCollide
        noclipLoop = runService.Stepped:Connect(function()
            if character then
                setCharacterCanCollide(character, false)
            end
        end)
    else
        -- Desativa o loop e restaura CanCollide
        if noclipLoop then
            noclipLoop:Disconnect()
        end
        if character then
            setCharacterCanCollide(character, true)
        end
    end
end

-- Adiciona o botão de alternância "Noclip"
local Toggle = AddToggle(Main, {
    Name = " اخترق الجدار",
    Default = false,
    Callback = onNoclipToggle
})

AddButton(Main, {
  Name = "فريمات ",
  Callback = function()
    -- FPS and Ping Checker Script (Improved UI with Movable Frame)

-- Create a ScreenGui to display FPS and Ping
local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "PerformanceGui"
ScreenGui.ResetOnSpawn = false -- Keep the UI persistent across respawns
ScreenGui.Parent = game.Players.LocalPlayer:WaitForChild("PlayerGui")

-- Frame for FPS and Ping display
local displayFrame = Instance.new("Frame")
displayFrame.Size = UDim2.new(0, 250, 0, 100)
displayFrame.Position = UDim2.new(0, 10, 0, 10)
displayFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
displayFrame.BackgroundTransparency = 0.4
displayFrame.BorderSizePixel = 0
displayFrame.Active = true -- Make the frame active for input events
displayFrame.Draggable = true -- Enable draggable frame
displayFrame.Parent = ScreenGui

-- FPS Label
local fpsLabel = Instance.new("TextLabel")
fpsLabel.Size = UDim2.new(1, -20, 0, 40)
fpsLabel.Position = UDim2.new(0, 10, 0, 10)
fpsLabel.TextColor3 = Color3.new(1, 1, 1)
fpsLabel.TextStrokeTransparency = 0.7
fpsLabel.TextSize = 24
fpsLabel.Font = Enum.Font.SourceSansBold
fpsLabel.TextXAlignment = Enum.TextXAlignment.Left
fpsLabel.BackgroundTransparency = 1
fpsLabel.Text = "FPS: Loading..."
fpsLabel.Parent = displayFrame

-- Ping Label
local pingLabel = Instance.new("TextLabel")
pingLabel.Size = UDim2.new(1, -20, 0, 40)
pingLabel.Position = UDim2.new(0, 10, 0, 50)
pingLabel.TextColor3 = Color3.new(1, 1, 1)
pingLabel.TextStrokeTransparency = 0.7
pingLabel.TextSize = 24
pingLabel.Font = Enum.Font.SourceSansBold
pingLabel.TextXAlignment = Enum.TextXAlignment.Left
pingLabel.BackgroundTransparency = 1
pingLabel.Text = "Ping: Loading..."
pingLabel.Parent = displayFrame

-- FPS Checker
local fps = 0
local lastTime = tick()

game:GetService("RunService").RenderStepped:Connect(function()
    fps = math.floor(1 / (tick() - lastTime))
    lastTime = tick()
    fpsLabel.Text = "FPS: " .. tostring(fps)
end)

-- Ping Checker
local function getPing()
    local player = game.Players.LocalPlayer
    local ping = player:GetNetworkPing() * 1000 -- Convert to milliseconds
    return math.floor(ping)
end

game:GetService("RunService").Stepped:Connect(function()
    local ping = getPing()
    pingLabel.Text = "Ping: " .. tostring(ping) .. " ms"
end)

-- Optional: Auto-adjust label colors based on performance
game:GetService("RunService").Stepped:Connect(function()
    if fps < 30 then
        fpsLabel.TextColor3 = Color3.new(1, 0, 0) -- Red for low FPS
    else
        fpsLabel.TextColor3 = Color3.new(0, 1, 0) -- Green for good FPS
    end

    if getPing() > 200 then
        pingLabel.TextColor3 = Color3.new(1, 0, 0) -- Red for high ping
    else
        pingLabel.TextColor3 = Color3.new(0, 1, 0) -- Green for good ping
    end
end)

-- Optional: Saving frame position locally
local function savePosition()
    local pos = displayFrame.Position
    -- Save the position to a datastore or local storage (optional implementation)
end

-- Saving the position when dragging stops
displayFrame.MouseLeave:Connect(savePosition)
displayFrame.InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 then
        savePosition()
    end
end)
    end
    })

local section = AddSection(Main, {"ممكن تحتاجها"})

local Paragraph = AddParagraph(Main, {"النجوم الي تطلع ضوء"})
AddButton(Main, {
  Name = "برتقالي ",
  Callback = function()
    local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0004FreeOrange"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "ازرق ",
  Callback = function()
    local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0006FreeBlue"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "بنفسجي ",
  Callback = function()
local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0007FreePurple"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "وردي ",
  Callback = function()
local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0008FreePink"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "احمر ",
  Callback = function()
local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0009FreeRed"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})
AddButton(Main, {
  Name = "ابيض",
  Callback = function()
local args = {
    [1] = "RequestingEmmitersName",
    [2] = "0002FreeWhite"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
  end
})

local Main = MakeTab({Name = "تنقل بواسطه gghali33 "})

local Paragraph = AddParagraph(Main, {"ادوات التنقل", "bom dia meus manos"})

local plrs = game.Players

-- Fetch all player names
local playerNames = {}
local players = plrs:GetPlayers()

for _, player in ipairs(players) do
    table.insert(playerNames, player.Name)
end

local Dropdown = AddDropdown(Main, {
  Name = playerNames[1] or "No Players",
  Options = playerNames,
  Default = "2",
  Callback = function(selectedplrName)
    plrs:FindFirstChild(selectedplrName)
        local targetPlayer = plrs:FindFirstChild(selectedplrName)
        if targetPlayer and targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
            -- Teleporting your character to the selected player's position
            local targetPosition = targetPlayer.Character.HumanoidRootPart.Position
            local localPlayerRoot = plrs.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")

            if localPlayerRoot then
                localPlayerRoot.CFrame = CFrame.new(targetPosition)
            end
        end
        print(selectedplrName)

  end
})
AddButton(Main, {
  Name = "تنقل ",
  Callback = function()
    mouse = game.Players.LocalPlayer:GetMouse()

tool = Instance.new("Tool")

tool.RequiresHandle = false

tool.Name = "اداة تنقل| Slow Scrpit"

tool.Activated:connect(function()

local pos = mouse.Hit+Vector3.new(0,2.5,0)

pos = CFrame.new(pos.X,pos.Y,pos.Z)

game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = pos

end)

tool.Parent = game.Players.LocalPlayer.Backpack
  end
})
local Slider = AddSlider(Main, {
  Name = "مسافة تنقل",
  MinValue = 10,
  MaxValue = 50,
  Default = 25,
  Increase = 1,
  Callback = function(Value)

  end
})
local Paragraph = AddParagraph(Main, {"جميع البيوت", "bom dia meus manos"})

-- Function to teleport to Teleport
local function teleportTohome1()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(258, 5, 222)
end

AddButton(Main, {
  Name = "البيت 1",
  Description = "",
  Callback = teleportTohome1
})

-- Function to teleport to Teleport
local function teleportTohome2()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(221, 5, 230)
end

AddButton(Main, {
  Name = "البيت 2",
  Description = "",
  Callback = teleportTohome2
})

-- Function to teleport to Teleport
local function teleportTohome3()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(262, 20, 223)
end

AddButton(Main, {
  Name = "البيت 3",
  Description = "",
  Callback = teleportTohome3
})

-- Function to teleport to Teleport
local function teleportTohome4()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(222, 20, 226)
end

AddButton(Main, {
  Name = "البيت 4",
  Description = "",
  Callback = teleportTohome4
})

-- Function to teleport to Teleport
local function teleportTohome5()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(159, 20, 226)
end

AddButton(Main, {
  Name = "البيت 5",
  Description = "",
  Callback = teleportTohome5
})

-- Function to teleport to Teleport
local function teleportTohome6()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-34, 17, -119)
end

AddButton(Main, {
  Name = "البيت 6",
  Description = "",
  Callback = teleportTohome6
})

-- Function to teleport to Teleport
local function teleportTohome7()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-38, 33, -119)
end

AddButton(Main, {
  Name = "البيت 7",
  Description = "",
  Callback = teleportTohome7
})

-- Function to teleport to Teleport
local function teleportTohome11()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-21, 32, 436)
end

AddButton(Main, {
  Name = "البيت 11",
  Description = "",
  Callback = teleportTohome11
})

-- Function to teleport to Teleport
local function teleportTohome12()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(155, 32, 433)
end

AddButton(Main, {
  Name = "البيت 12",
  Description = "",
  Callback = teleportTohome12
})

-- Function to teleport to Teleport
local function teleportTohome13()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(255, 33, 431)
end

AddButton(Main, {
  Name = "البيت 13",
  Description = "",
  Callback = teleportTohome13
})

-- Function to teleport to Teleport
local function teleportTohome14()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(245, 32, 394)
end

AddButton(Main, {
  Name = "البيت 14",
  Description = "",
  Callback = teleportTohome14
})

-- Function to teleport to Teleport
local function teleportTohome15()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(145, 32, 391)
end

AddButton(Main, {
  Name = "البيت 15",
  Description = "",
  Callback = teleportTohome15
})

-- Function to teleport to Teleport
local function teleportTohome16()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-24, 32, 390)
end

AddButton(Main, {
  Name = "البيت 16",
  Description = "",
  Callback = teleportTohome16
})

-- Function to teleport to Teleport
local function teleportTohome17()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-185, 32, -248)
end

AddButton(Main, {
  Name = "البيت 17",
  Description = "",
  Callback = teleportTohome17
})

-- Function to teleport to Teleport
local function teleportToGasStation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(192, 4, 272)
end

-- Function to teleport to Teleport
local function teleportTohome18()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-346, 32, -248)
end

AddButton(Main, {
  Name = "البيت 18",
  Description = "",
  Callback = teleportTohome18
})

-- Function to teleport to Teleport
local function teleportTohome20()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-460, 32, -291)
end

AddButton(Main, {
  Name = "البيت 20",
  Description = "",
  Callback = teleportTohome20
})

-- Function to teleport to Teleport
local function teleportTohome21()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-353, 32, -291)
end

AddButton(Main, {
  Name = "البيت 21",
  Description = "",
  Callback = teleportTohome21
})

-- Function to teleport to Teleport
local function teleportTohome22()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-193, 32, -291)
end

AddButton(Main, {
  Name = "البيت 22",
  Description = "",
  Callback = teleportTohome22
})

-- Function to teleport to Teleport
local function teleportTohome23()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-409, 64, -441)
end

AddButton(Main, {
  Name = "البيت 23",
  Description = "",
  Callback = teleportTohome23
})

-- Function to teleport to Teleport
local function teleportTohome24()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-359, 63, -495)
end

AddButton(Main, {
  Name = "البيت 24",
  Description = "",
  Callback = teleportTohome24
})

-- Function to teleport to Teleport
local function teleportTohome28()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-98, 1, 1075)
end

AddButton(Main, {
  Name = "البيت 28",
  Description = "",
  Callback = teleportTohome28
})

-- Function to teleport to Teleport
local function teleportTohome29()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-733, 1, 778)
end

AddButton(Main, {
  Name = "البيت 29",
  Description = "",
  Callback = teleportTohome29
})

-- Function to teleport to Teleport
local function teleportTohome30()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-232, -4 , 788)
end

AddButton(Main, {
  Name = "البيت 30",
  Description = "",
  Callback = teleportTohome30
})

-- Function to teleport to Teleport
local function teleportTohome31()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(611, 72, -333)
end

AddButton(Main, {
  Name = "البيت 31",
  Description = "",
  Callback = teleportTohome31
})

-- Function to teleport to Teleport
local function teleportTohome32()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-878, 1, -344)
end

AddButton(Main, {
  Name = "البيت 32",
  Description = "",
  Callback = teleportTohome32
})

-- Function to teleport to Teleport
local function teleportTohome33()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-144, 64, -417)
end

AddButton(Main, {
  Name = "البيت 33",
  Description = "",
  Callback = teleportTohome33
})

-- Function to teleport to Teleport
local function teleportTohome34()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(261, 32, 566)
end

AddButton(Main, {
  Name = "البيت 34",
  Description = "",
  Callback = teleportTohome34
})

-- Function to teleport to Teleport
local function teleportTohome35()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-31, 0, 2210)
end

AddButton(Main, {
  Name = "البيت 35",
  Description = "",
  Callback = teleportTohome35
})

-- Function to teleport to Teleport
local function teleportTohome36()
  game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(249, 21, -2295)
end

AddButton(Main, {
  Name = "البيت 36",
  Description = "",
  Callback = teleportTohome36
})

AddButton(Main, {
    Name = "خلف البيوت",
    Description = "",
    Callback = teleportToGasStation
})

-- Function to teleport to Teleport
local function teleportToCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(136, 4, 117)
end

AddButton(Main, {
    Name = "امام البيوت",
    Description = "",
    Callback = teleportToCenter
})

-- Function to teleport to Criminal
local function teleportToCriminal()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-119, -28, 235)
end

local Paragraph = AddParagraph(Main, {"اماكن ثانيه", "bom dia meus manos"})

AddButton(Main, {
    Name = "مكان اسلحة",
    Description = "Teleporta para as coordenadas do Criminal",
    Callback = teleportToCriminal
})

-- Function to teleport to House Abandoned
local function teleportToHouseAbandoned()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(986, 4, 63)
end

AddButton(Main, {
    Name = "بيت مسكون",
    Description = "Teleporta para as coordenadas da Casa Abandonada",
    Callback = teleportToHouseAbandoned
})

-- Function to teleport to Portal Agency
local function teleportToPortalAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(672, 4, -296)
end

AddButton(Main, {
    Name = "مكان سري",
    Description = "Teleporta para as coordenadas do Portal da Agência",
    Callback = teleportToPortalAgency
})

-- Function to teleport to Brooks Diner
local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(161, 8, 52)
end

AddButton(Main, {
    Name = "قهوة",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})

local function teleportToBrooksDiner()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-26, 4, -23)
end

AddButton(Main, {
    Name = "البداية",
    Description = "Teleporta para as coordenadas do Brooks Diner",
    Callback = teleportToBrooksDiner
})
-- Function to teleport to Hospital
local function teleportToHospital()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-309, 4, 71)
end

AddButton(Main, {
    Name = "مستشفى",
    Description = "Teleporta para as coordenadas do Hospital",
    Callback = teleportToHospital
})

-- Function to teleport to Arch
local function teleportToArch()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-589, 141, -59)
end

AddButton(Main, {
    Name = "فوق الجسر",
    Description = "Teleporta para as coordenadas do Arco",
    Callback = teleportToArch
})

-- Function to teleport to Agency
local function teleportToAgency()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(179, 4, -464)
end

AddButton(Main, {
    Name = "مكان الكهرباء",
    Description = "Teleporta para as coordenadas da Agência",
    Callback = teleportToAgency
})

-- Function to teleport to Secret Room in Workshop
local function teleportToSecretRoomInWorkshop()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(0, 4, -495)
end

AddButton(Main, {
    Name = "جوه الأرض",
    Description = "Teleporta para as coordenadas da Sala Secreta na Oficina",
    Callback = teleportToSecretRoomInWorkshop
})

-- Function to teleport to Secret Room 2
local function teleportToSecretRoom2()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-343, 4, -613)
end

AddButton(Main, {
    Name = "جوه الأرض 2",
    Description = "Teleporta para as coordenadas da Sala Secreta 2",
    Callback = teleportToSecretRoom2
})
-- Function to teleport to Secret Location
local function teleportToSecretLocation()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(505, -75, 143)
end

AddButton(Main, {
    Name = " 3 جوه الأرض",
    Description = "Teleporta para as coordenadas do Local Secreto",
    Callback = teleportToSecretLocation
})
-- Function to teleport to Island 1
local function teleportToIsland1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-1925, 23, 127)
end

AddButton(Main, {
    Name = "جزيرة 1",
    Description = "Teleporta para as coordenadas da Ilha 1",
    Callback = teleportToIsland1
})

-- Function to teleport to Airport
local function teleportToAirport()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(310, 5, 31)
end

AddButton(Main, {
    Name = "مطار",
    Description = "Teleporta para as coordenadas do Aeroporto",
    Callback = teleportToAirport
})

-- Function to teleport to Hotel Center
local function teleportToHotelCenter()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(182, 4, 150)
end

AddButton(Main, {
    Name = "البيوت",
    Description = "Teleporta para as coordenadas do Centro dos Hotéis",
    Callback = teleportToHotelCenter
})

-- Function to teleport to Lower Houses
local function teleportToLowerHouses()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(63, 35, 410)
end

AddButton(Main, {
    Name = " نص الشارع",
    Description = "Teleporta para as coordenadas das Casas Inferiores",
    Callback = teleportToLowerHouses
})

-- Function to teleport to Mountain 1
local function teleportToMountain1()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-670, 251, 765)
end

AddButton(Main, {
    Name = "فوق الجبل",
    Description = "Teleporta para as coordenadas da Montanha 1",
    Callback = teleportToMountain1
})

-- Function to teleport to On Top of School
local function teleportToOnTopOfSchool()
    game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-370, 50, 173)
end

AddButton(Main, {
    Name = "فوق المدرسة",
    Description = "Teleporta para as coordenadas Em Cima da Escola",
    Callback = teleportToOnTopOfSchool
})

local Main = MakeTab({Name = "الاسماء"})


AddTextBox(Main, {
  Name = "تغيير الاسم",
  Default = "",
  PlaceholderText = "اكتب اسمك هنا",
  ClearText = true,
  Callback = function(Value)
      local args = {
          [1] = "RolePlayName",
          [2] = Value
      }

      local success, error = pcall(function()
          game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
      end)

      if not success then
          warn("Error setting name:", error)
      end
  end
})

AddTextBox(Main, {
  Name = "تغيير البايو",
  Default = "",
  PlaceholderText = "اكتب البايو هنا",
  ClearText = true,
  Callback = function(Value)
      local args = {
          [1] = "RolePlayBio",
          [2] = Value
      }

      local success, error = pcall(function()
          game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
      end)

      if not success then
          warn("Error setting name:", error)
      end
  end
})


AddButton(Main, {
    Name = "ريم",
    Callback = function()
                local args = {
                    [1] = "RolePlayName",
                    [2] = "ريــــــــــــــــــــــــــــــــــــم"
                }

                game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
            end
        })

  AddButton(Main, {
    Name = "فاطمة",
    Callback = function()
        local args = {
            [1] = "RolePlayName",
            [2] = "فــــــــــاطــــمــــــة"
        }

        game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "ليان",
    Callback = function()
        local args = {
            [1] = "RolePlayName",
            [2] = "لــــــيـــــان"
        }

        game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "محمد",
    Callback = function()
        local args = {
            [1] = "RolePlayName",
            [2] = "محمد"
        }

        game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "خالد",
    Callback = function()
    print("work !!")local args = {
        [1] = "RolePlayName",
        [2] = "خالد"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "مكسيكي",
    Callback = function()
    print("work !!")
    local args = {
        [1] = "RolePlayName",
        [2] = "مكسيكي"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "نايف",
    Callback = function()
    print("work !!")        local args = {
        [1] = "RolePlayName",
        [2] = "نايف"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "علي",
    Callback = function()
    print("work !!")        local args = {
        [1] = "RolePlayName",
        [2] = "عــــــــلـــــي"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "حمد",
    Callback = function()
    print("work !!")    local args = {
        [1] = "RolePlayName",
        [2] = "حـــــــمـــــــد"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  AddButton(Main, {
    Name = "عبدالله",
    Callback = function()
    print("work !!")        local args = {
        [1] = "RolePlayName",
        [2] = "عـــــبــــدالـــلـــه"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1RPNam1eTex1t"):FireServer(unpack(args))
    end
  })

  local section = AddSection(Main, {"قريبا..."})


local Main = MakeTab({Name = "البيت"})
          AddButton(Main, {
            Name = "سبام فتح وقفل",
            Callback = function()
                spawn(function()
                    while task.wait() do
                        local args = {
                            [1] = "GarageDoor"
                        }
                        game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
                    end
                end)
            end
        })

          AddButton(Main, {
            Name = "  	فتح وغلق شباك ",
            Callback = function()
                              local args = {
                                  [1] = "Curtains"
                              }
                              game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
          end
          })

          AddButton(Main, {
            Name = " قفل باب بيت ",
            Callback = function()
                              local args = {
                                  [1] = "LockDoors"
                              }
                              game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Player1sHous1e"):FireServer(unpack(args))
          end
          })


          AddDropdown(Main, {
            Name = "التحكم في البيت",
            Default = "اختر رقم البيت",
            Options = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24"},
            Callback = function(Value)
                _G.SelectedHouse = Value -- Store selected house number globally
            end
        })

        AddButton(Main, {
          Name = "اخذ صلاحيات البيت",
          Callback = function()
              if _G.SelectedHouse then
                  local args = {
                      [1] = "GivePermissionLoopToServer",
                      [2] = game:GetService("Players").LocalPlayer,
                      [3] = tonumber(_G.SelectedHouse)
                  }

                  local success, error = pcall(function()
                      game:GetService("ReplicatedStorage").RE:FindFirstChild("1Playe1rTrigge1rEven1t"):FireServer(unpack(args))
                  end)

                  if not success then
                      warn("Error:", error)
                  end
              end
          end
      })

    local Main = MakeTab({Name = " رؤوس ورجل"})
    local Paragraph = AddParagraph(Main, {"الرؤوس", "bom dia meus manos"})
    AddButton(Main, {
      Name = "راس روبوت",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 1,
            [5] = 1,
            [6] = 3210773801
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })

    AddButton(Main, {
      Name = "راس المخفي",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 1,
            [5] = 1,
            [6] = 134082579
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    AddButton(Main, {
      Name = "راس رول و الكوبي",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 1,
            [5] = 1,
            [6] = 746767604
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    AddButton(Main, {
      Name = " عيون الزرقاء ",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 1,
            [5] = 1,
            [6] = 16580493236
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    local Paragraph = AddParagraph(Main, {"الارجل", "bom dia meus manos"})
    AddButton(Main, {
      Name = "رجل العظام الاسود مش شغال قيد التطوير ",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 14547162578,
            [5] = 1,
            [6] = 1
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    AddButton(Main, {
      Name = "رجل مقطوع",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 139607718,
            [5] = 1,
            [6] = 1
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    AddButton(Main, {
      Name = "رجل العظام رصاصي ",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 17500249989,
            [5] = 1,
            [6] = 1
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })
    AddButton(Main, {
      Name = "رجل رول ",
      Callback = function()
        print("Clicked")local args = {
        [1] = "CharacterChange",
        [2] = {
            [1] = 1,
            [2] = 1,
            [3] = 1,
            [4] = 3230472745,
            [5] = 1,
            [6] = 1
        },
        [3] = "Roblox20"
    }

    game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))
      end
    })

    local Main = MakeTab({Name = "الاجسام"})
local Paragraph = AddParagraph(Main, {"اجسام البنات"})

AddButton(Main, {
  Name = "جـسـم بـنـت  Blush Fashion ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 96491916349570,
[2] = 76683091425509,
[3] = 75159926897589,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  Fashion Doll ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 74302534603111,
[2] = 76683091425509,
[3] = 75159926897589,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "جـسـم بـنـت  Modern Woman ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 124754866635882,
[2] = 76683091425509,
[3] = 75159926897589,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})
AddButton(Main, {
  Name = "جـسـم بـنـت  Chibi Doll  ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 96491916349570,
[2] = 14854350570,
[3] = 14854350451,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  Baddie Doll",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 101577365085156,
[2] = 121017849910260,
[3] = 111571034664628,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  PoP Doll ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 18839824113,
[2] = 18839824209,
[3] = 18839824132,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  Pie Doll -",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 16214246112,
[2] = 16214249513,
[3] = 16214251181,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  Y2K Gal ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 15539008532,
[2] = 15539008875,
[3] = 15539008680,
[4] = 15539008795,
[5] = 15539011945,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم بـنـت  Chibi Person ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 14861800638,
[2] = 14861800626,
[3] = 14861801452,
[4] = 14861800627,
[5] = 14861801454,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

local Paragraph = AddParagraph(Main, {"اجسام الاولاد"})

AddButton(Main, {
  Name = "جـسـم ولـد  S15 Skinned ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 17754346388,
[2] = 1,
[3] = 1,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم ولـد  Thin ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 92757812011061,
[2] = 99519402284266,
[3] = 115905570886697,
[4] = 1,
[5] = 1,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم ولـد  كـوبـي ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 86499666,
[2] = 27112039,
[3] = 27112052,
[4] = 27112068,
[5] = 27112056,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})


AddButton(Main, {
  Name = "جـسـم ولـد  رول ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 27112025,
[2] = 27112039,
[3] = 27112052,
[4] = 3230472745,
[5] = 3230470862,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

AddButton(Main, {
  Name = "جـسـم ولـد  عـضـلات ",
  Callback = function()
print("Clicked")local args = {
[1] = "CharacterChange",
[2] = {
[1] = 18178775358,
[2] = 18178775182,
[3] = 18178775725,
[4] = 18178777453,
[5] = 18178775695,
[6] = 1
},
[3] = "YinHub"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(unpack(args))

  end
})

local Main = MakeTab({Name = "الدمج الاشعور"})

local Paragraph = AddParagraph(Main, {" دمج شعر الابيض حطها وحط الباقي وياه"})
AddButton(Main, {
  Name = " الدمج الابيض حطها وحط الباقي",
  Callback = function()
    local args = {
    [1] = "wearWalkStyle",
    [2] = 14627127264,
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))
end
})
AddButton(Main, {
  Name = " تكملة الدمج الابيض ",
  Callback = function()
    local args = {
    [1] = "wearWalkStyle",
    [2] = 15908583844,
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))
end
})
AddButton(Main, {
  Name = "  تكملة الدمج الابيض ",
  Callback = function()
    local args = {
    [1] = "wearWalkStyle",
    [2] = 14808889186,
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))
end
})
AddButton(Main, {
  Name = " تكملة الدمج الابيض",
  Callback = function()
    local args = {
    [1] = "wearWalkStyle",
    [2] = 15349539978,
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer(unpack(args))
end
})

local Main = MakeTab({Name = "اشعارات"})

-- Global variable to track notification state
_G.NotificationsEnabled = true

-- Function to show notification if enabled
local function ShowNotification(title, text, duration)
    if _G.NotificationsEnabled then
        game:GetService("StarterGui"):SetCore("SendNotification", {
            Title = title,
            Text = text,
            Duration = duration or 3
        })
    end
end

-- Handle player joining
game.Players.PlayerAdded:Connect(function(player)
    ShowNotification(
        "دخول لاعب",
        player.Name .. " دخل اللعبة"
    )
end)

-- Handle player leaving
game.Players.PlayerRemoving:Connect(function(player)
    ShowNotification(
        "خروج لاعب",
        player.Name .. " غادر اللعبة"
    )
end)

-- Toggle for join/leave notifications
AddToggle(Main, {
    Name = "اشعارات دخول وخروج",
    Default = true,
    Callback = function(Value)
        _G.NotificationsEnabled = Value
    end
})

-- Toggle for game notifications
AddToggle(Main, {
    Name = "اشعارات النظام",
    Default = true,
    Callback = function(Value)
        _G.SystemNotificationsEnabled = Value

        -- Example system notification when toggled
        if Value then
            ShowNotification(
                "النظام",
                "تم تفعيل اشعارات النظام",
                5
            )
        end
    end
})

-- Toggle for kill notifications
AddToggle(Main, {
    Name = "اشعارات القتل",
    Default = true,
    Callback = function(Value)
        _G.KillNotificationsEnabled = Value

        -- Example kill notification when toggled
        if Value then
            ShowNotification(
                "القتل",
                "تم تفعيل اشعارات القتل",
                5
            )
        end
    end
})

-- Button to test notifications
AddButton(Main, {
    Name = "اختبار الاشعارات",
    Callback = function()
        ShowNotification(
            "اختبار",
            "هذا اختبار للاشعارات",
            3
        )
    end
})

local Main = MakeTab({Name = "السكنات"})

AddButton(Main, {
  Name = "نسخ سكنات",
Callback = function()
local gui = Instance.new("ScreenGui")
gui.Name = "GazerGui"
gui.Parent = cloneref(game.CoreGui) or game.CoreGui


local function RESETBLOCK()
local args = {
    [1] = "CharacterChange",
    [2] = {
        [1] = 0,
        [2] = 0,
        [3] = 0,
        [4] = 0,
        [5] = 0,
        [6] = 0
    },
    [3] = "AllBlocky"
}

game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Avata1rOrigina1l"):FireServer(unpack(args))
end




local function APPLY_SKINTONE(Player)
    local p = Player
    local c = p.Character or p.CharacterAdded:Wait()
    local h = c:FindFirstChildOfClass("Humanoid")

    if not h then
        warn("Humanoid not found!")
        return
    end

    local bodyColors = c:FindFirstChildOfClass("BodyColors")

    if not bodyColors then
        warn("BodyColors not found!")
        return
    end

    -- Get skin tone (use HeadColor or any other body part color)
    local skinTone = bodyColors.HeadColor

    -- Convert BrickColor to readable string
    local skinToneName = skinTone.Name

    -- Fire the RemoteEvent with the detected skin tone
    local args = {
        [1] = "skintone",
        [2] = skinToneName
    }

    game:GetService("ReplicatedStorage"):WaitForChild("RE"):WaitForChild("1Updat1eAvata1r"):FireServer(unpack(args))
end

local function Wear(id)
game:GetService("ReplicatedStorage").RE:FindFirstChild("1Updat1eAvata1r"):FireServer("wear", id) end


local function COPYCLOTHING(Player)
    local p = Player
    local c = p.Character or p.CharacterAdded:Wait()
    local h = c:FindFirstChildOfClass("Humanoid")

    if not h then
        warn("Humanoid not found!")
        return
    end

    local d = h:GetAppliedDescription()
    local cIds = { d.Shirt, d.Pants, d.GraphicTShirt }
    local done = false

    task.spawn(function()
        for _, id in ipairs(cIds) do
            if id ~= 0 then
                task.wait(1)
                Wear(id)
            end
        end
        done = true
    end)

    repeat task.wait() until done -- Ensure the function waits until completion
end

local function COPYBODYPART(Player)
    local p = Player
    local c = p.Character or p.CharacterAdded:Wait()
    local h = c:FindFirstChildOfClass("Humanoid")

    if not h then
        warn("Humanoid not found!")
        return
    end

    local d = h:GetAppliedDescription()

    local bIds = {
        d.Torso,
        d.RightArm,
        d.LeftArm,
        d.RightLeg,
        d.LeftLeg,
        d.Head
    }

    local done = false
    task.spawn(function()
        game:GetService("ReplicatedStorage").RE:FindFirstChild("1Avata1rOrigina1l"):FireServer(
            "CharacterChange",
            bIds,
            "GAZE"
        )
        done = true
    end)

    repeat task.wait() until done
end

local function COPYACCESSORIES(Player)
    local p = Player
    local c = p.Character or p.CharacterAdded:Wait()
    local h = c:FindFirstChildOfClass("Humanoid")

    if not h then
        warn("Humanoid not found!")
        return
    end

    local d = h:GetAppliedDescription()
    local aIds = {}

    for _, aList in ipairs({
        d.HatAccessory,
        d.HairAccessory,
        d.FaceAccessory,
        d.NeckAccessory,
        d.ShouldersAccessory,
        d.FrontAccessory,
        d.BackAccessory,
        d.WaistAccessory
    }) do
        for id in string.gmatch(aList, "%d+") do
            table.insert(aIds, tonumber(id))
        end
    end

    local done = false
    task.spawn(function()
        for _, id in ipairs(aIds) do
            task.wait(1)
            Wear(id)
        end
        done = true
    end)

    repeat task.wait() until done
end



local function START(displayName)
    local player = nil
    displayName = string.lower(displayName)
    for _, plr in ipairs(game.Players:GetPlayers()) do
        local playerNameLower = string.lower(plr.Name)
        local playerDisplayNameLower = string.lower(plr.DisplayName)
        if string.find(playerNameLower, displayName, 1, true) or string.find(playerDisplayNameLower, displayName, 1, true) then
            player = plr
            break
        end
    end

    if player then

    COPYACCESSORIES(game.Players.LocalPlayer)
    COPYACCESSORIES(player)
    wait(1)
    RESETBLOCK()
    wait(3)
    COPYBODYPART(player)
    COPYCLOTHING(player)
    APPLY_SKINTONE(player)



end
end


-- put your mainframe into the screengui that I have made (frame.Parent = gui)

local GazerMain = Instance.new("Frame")
GazerMain.Size = UDim2.new(0.4, 0, 0.4, 0)
GazerMain.Position = UDim2.new(0.5, -GazerMain.Size.X.Offset / 2, 0.5, -GazerMain.Size.Y.Offset / 2)
GazerMain.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
GazerMain.BackgroundTransparency = 0.2
GazerMain.BorderSizePixel = 0
GazerMain.Active = true
GazerMain.Draggable = true
GazerMain.Parent = gui

local UICorner = Instance.new("UICorner")
UICorner.CornerRadius = UDim.new(0.1, 0)
UICorner.Parent = GazerMain

local GazerTitle = Instance.new("TextLabel")
GazerTitle.Size = UDim2.new(1, 0, 0.2, 0)
GazerTitle.Position = UDim2.new(0, 0, 0, 0)
GazerTitle.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
GazerTitle.BackgroundTransparency = 0.2
GazerTitle.BorderSizePixel = 0
GazerTitle.Text = "نسخ سكنات من المطور سيف"
GazerTitle.TextScaled = true
GazerTitle.Font = Enum.Font.GothamBold
GazerTitle.TextColor3 = Color3.fromRGB(255, 255, 255)
GazerTitle.Parent = GazerMain

local UICornerTitle = Instance.new("UICorner")
UICornerTitle.CornerRadius = UDim.new(0.1, 0)
UICornerTitle.Parent = GazerTitle

local EnterName = Instance.new("TextBox")
EnterName.Size = UDim2.new(0.85, 0, 0.2, 0)
EnterName.Position = UDim2.new(0.075, 0, 0.3, 0)
EnterName.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
EnterName.Text = ""
EnterName.BackgroundTransparency = 0.2
EnterName.BorderSizePixel = 0
EnterName.PlaceholderText = "اسم اللاعب"
EnterName.PlaceholderColor3 = Color3.fromRGB(150, 150, 150)
EnterName.TextColor3 = Color3.fromRGB(255, 255, 255)
EnterName.Font = Enum.Font.Gotham
EnterName.TextScaled = true
EnterName.ClearTextOnFocus = true
EnterName.Parent = GazerMain

local UICornerInput = Instance.new("UICorner")
UICornerInput.CornerRadius = UDim.new(0.1, 0)
UICornerInput.Parent = EnterName

local INFO = Instance.new("TextButton")
INFO.Size = UDim2.new(0.4, 0, 0.2, 0)
INFO.Position = UDim2.new(0.3, 0, 0.7, 0)
INFO.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
INFO.BackgroundTransparency = 0.2
INFO.BorderSizePixel = 0
INFO.Text = "انسخ!"
INFO.TextScaled = true

INFO.Font = Enum.Font.GothamBold
INFO.TextColor3 = Color3.fromRGB(255, 255, 255)
INFO.Parent = GazerMain

local UICornerButton = Instance.new("UICorner")
UICornerButton.CornerRadius = UDim.new(0.1, 0)
UICornerButton.Parent = INFO

INFO.MouseButton1Click:Connect(function()
    local displayName = EnterName.Text


    INFO.Size = UDim2.new(0, 0, 0, 0)

    START(displayName)
    wait(3)
    INFO.Size = UDim2.new(0.4, 0, 0.2, 0)



end)


end
})

local section = AddSection(Main, {"قريبا بحط سكنات ..."})

local Main = MakeTab({Name = "المركبات"})

local section = AddSection(Main, {"قريبا ..."})

local Main = MakeTab({Name = "قتل"})

AddButton(Main, {
  Name = "اخذ كنبة ",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})

AddButton(Main, {
  Name = "سكربت  القتل",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/0Ben1/fe./main/Fling%20GUI"))()
  end
})

local Main = MakeTab({Name = "اخرى"})

AddButton(Main, {
  Name = "اخذ كنبة ",
  Callback = function()
    local args={[1]="PickingTools",[2]="Couch"};game:GetService("ReplicatedStorage").RE:FindFirstChild("1Too1l"):InvokeServer(unpack(args))
  end
})

AddButton(Main, {
Name = " اعادة دخول الى سيرفر",
Callback = function()
  local ts = game:GetService("TeleportService")
      local p = game:GetService("Players").LocalPlayer
      ts:Teleport(game.PlaceId, p)
  print('Hello!')
end
})
AddButton(Main, {
Name = "احذف جميع الأشياء الي في ايدك",
Callback = function()
  local args = {
  [1] = "ClearAllTools"
}

game:GetService("ReplicatedStorage").RE:FindFirstChild("1Clea1rTool1s"):FireServer(unpack(args))
end
})

AddButton(Main, {
Name = "ازالة الملابس",
Callback = function()
--[[
	WARNING: Heads up! This script has not been verified by ScriptBlox. Use at your own risk!
]]
local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()

local function removeClothes()
    for _, item in pairs(character:GetChildren()) do
        if item:IsA("Shirt") or item:IsA("Pants") then
            item:Destroy()
        end
    end
end

removeClothes()
end
})
AddButton(Main, {
Name = "اقتل نفسك",
Callback = function()
  game.Players.LocalPlayer.Character.Humanoid.Health = 0
end
})
AddButton(Main, {
Name = "ازالة لاق ",
Callback = function()
  loadstring(game:HttpGet("https://raw.githubusercontent.com/CasperFlyModz/discord.gg-rips/main/FPSBooster.lua"))()
end
})


local Main = MakeTab({Name = "سكربتاتي"})

AddButton(Main, {
  Name = "سكربت الادمن",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/S2EXE/VIP_sCRIPT-HELL-YHHHHHHHHHHHH/refs/heads/main/HI"))()
  end
})

AddButton(Main, {
  Name = " سكربت مع المطور محمد ",
  Callback = function()
    loadstring(game:HttpGet("https://raw.githubusercontent.com/S2EXE/GUI12-/refs/heads/main/Protected_4176441765382601.txt"))()
  end
})

local section = AddSection(Main, {"ان شاء الله القادم افضل"})`
        },

        ];

        // ========================================
        // APPLICATION CODE
        // ========================================
        let currentScript = null;

        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            // Render script cards
            renderScriptCards();

            // Navigation functions
            document.getElementById('scripts-btn').addEventListener('click', function () {
                document.getElementById('scripts-section').scrollIntoView({ behavior: 'smooth' });
            });

            document.getElementById('about-btn').addEventListener('click', function () {
                document.getElementById('about-section').scrollIntoView({ behavior: 'smooth' });
            });

            // Typewriter effect for hacker text
            const hackerText = document.querySelector('.hacker-text');
            hackerText.style.width = '0';
            setTimeout(() => {
                hackerText.style.animation = 'typing 3s steps(40) forwards';
            }, 500);

            // Search functionality
            document.getElementById('scriptSearch').addEventListener('input', filterScripts);

            // Category filter
            document.querySelectorAll('.category-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    filterScripts();
                });
            });
        });

        // Render script cards
        function renderScriptCards() {
            const container = document.getElementById('scriptsContainer');
            container.innerHTML = '';

            FILES_DATA.forEach(script => {
                const card = document.createElement('div');
                card.className = 'script-card';
                card.setAttribute('data-name', script.name);
                card.setAttribute('data-category', script.category);
                card.setAttribute('onclick', `showScriptPreview('${script.id}')`);

                card.innerHTML = `
                    <div class="script-icon">
                        <i class="fas fa-file-code"></i>
                    </div>
                    <div class="script-name">${script.name}</div>
                    <div class="script-meta">
                        <span><i class="fas fa-download"></i> ${script.downloads}</span>
                        <span><i class="fas fa-hdd"></i> ${script.size}</span>
                    </div>
                    <div class="script-description">${script.description}</div>
                    <div class="link-status available">(الرابط متوفر)</div>
                    <div class="category-badge">${script.category}</div>
                `;

                container.appendChild(card);
            });
        }

        // Filter scripts based on search and category
        function filterScripts() {
            const searchTerm = document.getElementById('scriptSearch').value.toLowerCase();
            const activeCategory = document.querySelector('.category-btn.active').textContent;

            document.querySelectorAll('.script-card').forEach(card => {
                const name = card.getAttribute('data-name').toLowerCase();
                const category = card.getAttribute('data-category');
                const matchSearch = name.includes(searchTerm);
                const matchCategory = activeCategory === 'الكل' || category === activeCategory;

                card.style.display = (matchSearch && matchCategory) ? 'block' : 'none';
            });
        }

        // Show notification function
        function showNotification(type, message) {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);

            // Remove notification after animation
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        // Function to show script preview
        function showScriptPreview(scriptId) {
            const script = FILES_DATA.find(file => file.id === scriptId);
            if (!script) {
                showNotification('error', `سكربت ${scriptId} غير متوفر للمعاينة حالياً`);
                return;
            }

            currentScript = script;
            document.getElementById('scriptNamePreview').textContent = script.name;
            document.getElementById('scriptPreviewContent').innerHTML = script.content;
            document.getElementById('previewModal').classList.add('active');
        }

        // Close preview modal
        function closePreview() {
            document.getElementById('previewModal').classList.remove('active');
            currentScript = null;
        }

        // Download current script from preview modal
        function downloadCurrentScript() {
            if (currentScript) {
                downloadScript(currentScript.id);
            }
        }

        // Function to handle script download
        function downloadScript(scriptId) {
            const script = FILES_DATA.find(file => file.id === scriptId);
            if (!script) {
                showNotification('error', `رابط سكربت ${scriptId} غير متوفر حالياً، يرجى التواصل مع المطور`);
                return;
            }

            // Create download link using Blob
            const blob = new Blob([script.content], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);

            const downloadLink = document.createElement('a');
            downloadLink.href = url;
            downloadLink.download = `${script.name}.${script.type}`;
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);

            URL.revokeObjectURL(url);

            showNotification('success', `تم تنزيل سكربت ${script.name} بنجاح!`);
        }

        // Close modal when clicking outside
        window.addEventListener('click', function(event) {
            const modal = document.getElementById('previewModal');
            if (event.target === modal) {
                closePreview();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closePreview();
            }
        });
