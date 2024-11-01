const express = require("express");
const { MongoClient, ObjectId, Timestamp } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodeMailer = require("nodemailer");
require("dotenv").config();


const router = express.Router();
const url = process.env.MONGODB_URI;

let client;
(async () => {
  try {
    client = new MongoClient(url);
    await client.connect();
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
})();


//-----------------> Register Endpoint <-----------------//
router.post("/register", async (req, res) => {
  const { email, name, phone, password, username } = req.body;
  let error = "";

  if (!email || !name || !phone || !password || !username) {
    error = "All fields are required";
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

  
    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already used" });
    }


    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      email,
      name,
      phone,
      password: hashedPassword,
      username,
      accountCreated: new Date(),
      isEmailVerified: false, 
      projects: [],
      toDoList: [],
    };

    await userCollection.insertOne(newUser)

    const secret = process.env.JWT_SECRET + hashedPassword;
    const token = jwt.sign({email: newUser.email}, secret, {expiresIn: "5m",} );

    let link = `https://ganttify-5b581a9c8167.herokuapp.com/verify-email/${email}/${token}`;

    const transporter = nodeMailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    let mailDetails = {
      from: process.env.USER_EMAIL,
      to: email,
      subject: 'Verify Your Ganttify Account',
      text: `Hello ${newUser.name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
      html: `<p>Hello ${newUser.name},</p> <p>Please verify your Ganttify account by clicking the following link:\n</p> <a href="${link}" className="btn">Verify Account</a>`
    };

    transporter.sendMail(mailDetails, function (err, data) {
      if (err) {
        return res.status(500).json({ error: 'Error sending verification email' });
      } else {
        return res.status(200).json({ message: 'Verification email sent' });
      }
    });

  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


//---> Updated Email Verification 
router.post('/verify-email', async (req, res) => {
  const { token } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.status(404).send("User not found");
    }

    if(user.isEmailVerified) {
      return res.status(400).send("User already verified");
    }

    const secret = process.env.JWT_SECRET + user.password;

    jwt.verify(token, secret, async (err) => {
      if (err) {
        return res.status(403).send("Invalid or expired token");
      }

      await userCollection.updateOne({ email }, { $set: { isVerified: true } });

      res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
    });

  } catch (error) {
    console.error('Error during verification:', error);
    res.status(400).send("Invalid token format");
  }
});


router.get('/verify-email/:email/:token', async (req, res) => {
  const { email, token } = req.params;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const user = await userCollection.findOne({ email: email });

    if (user) {
      const secret = process.env.JWT_SECRET + user.password;

      try {
        jwt.verify(token, secret);

        await userCollection.updateOne({ _id: user._id }, { $set: { isEmailVerified: true } });

        res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
        
      } catch (error) {
        res.send("Invalid or expired token");
      }
    } else {
      return res.status(404).send("User does not exist");
    }
  } catch (error) {
    console.error('Error during verification:', error);
    res.status(400).send("Invalid ID format");
  }
});

let userList = [];
//-----------------> User List Endpoint <-----------------//
router.get("/userlist", (req, res) => {
  res.status(200).json({ users: userList });
});


//-----------Read Users Endpoint----------------//
router.post("/read/users", async (req, res) => {
    const { users } = req.body;
    let error = "";
    var usersInfo = [];
    
    if (!users) {
        error = "User ids are required";
        return res.status(400).json({ error });
    }
  
    try {
        for(let i = 0;i<users.length;i++){
            const db = client.db("ganttify");
            const results = db.collection("userAccounts");
        
          
            const user = await results.findOne({ _id:new ObjectId(users[i])});
            usersInfo.push(user);
        }

        if(!userList){
            error = "no users found";
            res.status(400).json({error});
        }
        else{
            res.status(200).json({usersInfo,error});
        }
        
    }
    catch (error) {
        console.error("Login error:", error);
        error = "Internal server error";
        res.status(500).json({ error });
    }
  });

//-----------------> Login Endpoint <-----------------//
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let error = "";

  if (!email || !password) {
    error = "Email and password are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");


    const user = await userCollection.findOne({ email });

    if (!user) {
      error = "Invalid email or password";
      return res.status(401).json({ error });
    }


    if (!user.isEmailVerified) {
      const secret = process.env.JWT_SECRET + user.password;
      const token = jwt.sign({ email: user.email }, secret, { expiresIn: "5m" });

      let link = `https://ganttify-5b581a9c8167.herokuapp.com/verify-email/${email}/${token}`;

      const transporter = nodeMailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL,
          pass: process.env.EMAIL_PASSWORD
        }
      });

      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Verify Your Ganttify Account',
        text: `Hello ${user.name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
        html: `<p>Hello ${user.name},</p> <p>Please verify your Ganttify account by clicking the following link:</p> <a href="${link}" className="btn">Verify Account</a>`
      };

      transporter.sendMail(mailDetails, function (err, data) {
        if (err) {
          return res.status(500).json({ error: 'Error sending verification email' });
        } else {
          return res.status(400).json({ error: 'Email not verified. Verification email sent again.' });
        }
      });
      return;
    }

 
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      error = "Invalid email or password";
      return res.status(401).json({ error });
    }


    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({
      token,
      _id: user._id,
      email: user.email,
      name: user.name,
      username: user.username,
      phone: user.phone,
      projects: user.projects,
      toDoList: user.toDoList,
      error: ""
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// TASK CRUD Operations
//-----------------> Create Task Endpoint <-----------------//

// Expression to validate hex color
const isValidHexColor = (color) => /^#([0-9A-F]{3}){1,2}$/i.test(color);


// List of valid patterns
// Replaced the valid file as pngs instead of svgs.
const allowedPatterns = {
  hollow_shape_family: [
    // "Hollow_Mac_Noodle_Density_1.svg", // Removed
    "Hollow_Single_Circle_Density_1.png",
    "Hollow_Single_Dot_Density_1.png",
    "Hollow_Single_Rhombus_Density_1.png",
    "Hollow_Single_Square_Density_1.png",
    "Hollow_Single_Star_Density_1.png",
    "Hollow_Single_Triangle_Density_1.png",
  ],
  line_family: [
    "Diagonal_Left_Single_Line_Density_1.png",
    "Diagonal_Right_Single_Line_Density_1.png",
    "Diagonal_Woven_Line_Density_1.png",
    "Single_Horizontal_Line_Density_1.png",
    "Single_Vertical_Line_Density_1.png",
  ],
  solid_shape_family: [
    // "Solid_Mac_Noodle_Density_1.svg", // Removed.
    "Solid_Single_Circle_Density_1.png",
    "Solid_Single_Dot_Density_1.png",
    "Solid_Single_Rhombus_Density_1.png",
    "Solid_Single_Square_Density_1.png",
    "Solid_Single_Star_Density_1.png",
    "Solid_Single_Triangle_Density_1.png",
  ], 
  halftone_family: [
    "Halftone_Density_1.png",
    "Halftone_Density_2.png",
    "Halftone_Density_3.png",
  ]
};

// Expression to validate pattern selection
const isValidPattern = (pattern) => {
  const [folder, file] = pattern.split('/');
  return allowedPatterns[folder] && allowedPatterns[folder].includes(file);
};

router.post("/createtask", async (req, res) => {
  const {
    description = "",
    dueDateTime,
    progress = "Not Started",
    assignedTasksUsers = [],
    taskTitle,
    tiedProjectId,
    taskCreatorId,
    startDateTime,
    color = "#DC6B2C",
    pattern = ""
  } = req.body;
  let error = "";

  if (!dueDateTime || !taskTitle || !taskCreatorId || !startDateTime) {
    error = "Task dueDateTime, taskTitle, taskCreatorId, and startDateTime are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const projectCollection = db.collection("projects");
    const userCollection = db.collection("userAccounts");

    const newTask = {
      description,
      dueDateTime: new Date(dueDateTime),
      taskCreated: new Date(),
      progress,
      assignedTasksUsers: assignedTasksUsers.map((id) => new ObjectId(id)),
      taskTitle,
      tiedProjectId: new ObjectId(tiedProjectId),
      taskCreatorId: new ObjectId(taskCreatorId),
      startDateTime: new Date(startDateTime),
      color,
      pattern
    };



    const task = await taskCollection.insertOne(newTask);
    const taskId = task.insertedId;

    await projectCollection.updateOne(
      { _id: new ObjectId(tiedProjectId) },
      { $push: { tasks: taskId } }
    );

    if (assignedTasksUsers.length > 0) {
      await userCollection.updateMany(
        { _id: { $in: assignedTasksUsers.map(id => new ObjectId(id)) } },
        { $push: { toDoList: taskId } }
      );
    }

    res.status(201).json({ ...newTask, _id: taskId });
  } catch (error) {
    console.error("Error creating task:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});


//-----------------> Read Task <-----------------//
router.get("/readtasks", async (req, res) => {
  let error = "";

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const tasks = await taskCollection.find({}).toArray();

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error finding tasks:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-----------------> Update Task <-----------------//
router.put("/tasks/:id", async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;
  let error = "";

  if (!Object.keys(updateFields).length) {
    error = "No fields provided to update";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    // Convert any provided ObjectId fields
    if (updateFields.assignedTasksUsers) {
      updateFields.assignedTasksUsers = updateFields.assignedTasksUsers.map(
        (id) => new ObjectId(id),
      );
    }
    if (updateFields.tiedProjectId) {
      updateFields.tiedProjectId = new ObjectId(updateFields.tiedProjectId);
    }
    if (updateFields.taskCreatorId) {
      updateFields.taskCreatorId = new ObjectId(updateFields.taskCreatorId);
    }
    if (updateFields.dueDateTime) {
      updateFields.dueDateTime = new Date(updateFields.dueDateTime);
    }

    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields },
    );
    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating task:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-----------------> Delete Task <-----------------//
router.delete("/tasks/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const result = await taskCollection.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json(result);
  } catch (error) {
    console.error("Error deleting task:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});


// -----------------> Assign user to a task <----------------- //
router.post("/assignusertotask", async (req, res) => {
  const { taskId, userId } = req.body;

  if (!taskId || !userId) {
    return res.status(400).json({ error: "Task ID and user ID are required" });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    //Check if the user is already assigned to the task
    const task = await taskCollection.findOne({
      _id: new ObjectId(taskId),
      assignedTasksUsers: new ObjectId(userId)
    });

    if (task) {
      return res.status(400).json({error: "User is already assigned to this task"});
    }

    // Update task to add user to assignedTasksUsers 
    const result = await taskCollection.updateOne(
      { _id: new ObjectId(taskId) },
      { $addToSet: { assignedTasksUsers: new ObjectId(userId) } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.status(200).json({ message: "User assigned to task successfully" });
  } catch (error) {
    console.error("Error assigning user to task:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// -----------------> Assign task to a project <----------------- //
router.post("/assigntaskstoproject", async (req, res) => {
  const { projectId, taskId } = req.body;
  let error = "";

  if (!projectId || !taskId || !Array.isArray(taskId) || taskId.length === 0) {
    error = "Project ID and an array of Task IDs are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");

    // Ensure the project exists
    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });
    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    // Ensure all tasks exist
    const tasks = await taskCollection.find({
      _id: { $in: taskId.map(id => new ObjectId(id)) }
    }).toArray();

    if (tasks.length !== taskId.length) {
      return res.status(404).json({ error: "One or more tasks not found" });
    }

    // Check if any of the tasks are already assigned to the project
    const assignedTasks = await taskCollection.find({
      _id: { $in: taskId.map(id => new ObjectId(id)) },
      tiedProjectId: new ObjectId(projectId)
    }).toArray();

    if (assignedTasks.length > 0) {
      const alreadyAssignedTasks = assignedTasks.map(task => task._id.toString());
      return res.status(400).json({ error: `Task is already assigned to this project` });
    }

    // Add taskId to the project's tasks array
    await projectCollection.updateOne(
      { _id: new ObjectId(projectId) },
      { $addToSet: { tasks: { $each: taskId.map(id => new ObjectId(id)) } } }
    );

    // Update each task's tiedProjectId field
    await taskCollection.updateMany(
      { _id: { $in: taskId.map(id => new ObjectId(id)) } },
      { $set: { tiedProjectId: new ObjectId(projectId) } }
    );

    res.status(200).json({ message: "Tasks assigned to project successfully" });
  } catch (error) {
    console.error("Error assigning tasks to project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Project CRUD Operations
//-----------------> Create a project <-----------------//
router.post("/createproject", async (req, res) => {
  const {
    nameProject,
    team,
    tasks,
    isVisible = 1,
    founderId,
    flagDeletion = 0,
    group,
  } = req.body;
  let error = "";

  if (!nameProject || !founderId) {
    error = "Project name and founder ID are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    const newProject = {
      nameProject,
      dateCreated: new Date(),
      team: new ObjectId(),
      tasks: [], 
      isVisible,
      founderId: new ObjectId(founderId),
      flagDeletion,
      group: [new ObjectId()],
    };

    const project = await projectCollection.insertOne(newProject);
    const projectId = project.insertedId;


    const newTeam = {founderId: new ObjectId(founderId), editors: [], members: [], projects: [projectId],};

    const team = await teamCollection.insertOne(newTeam);

  
    await projectCollection.updateOne(
      { _id: projectId },
      { $set: { team: team.insertedId } }
    );


    await userCollection.updateOne(
      { _id: new ObjectId(founderId) },
      { $push: { projects: projectId } }
    );

    res.status(201).json({ ...newProject, _id: projectId, team: team.insertedId });

  } catch (error) {

    console.error("Error creating project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
    
  }
});

//-----------------> Read all projects <-----------------//
router.get("/readprojects", async (req, res) => {
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const projects = await projectCollection.find({}).toArray();
    res.status(200).json(projects);
  } catch (error) {
    console.error("Error finding projects:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});


//-----------------> Read public projects only <-----------------//
router.get("/publicprojects", async (req, res) => {
  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const publicProjects = await projectCollection.find({ isVisible: 1 }).toArray();

    res.status(200).json(publicProjects);
  } catch (error) {
    console.error("Error fetching public projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// -----------------> Read specific projects <-----------------//
router.post("/readspecificprojects", async (req, res) => {
  const { projectId } = req.body; // Assuming projectIds is an array of _id values

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const projects = await projectCollection.find({
      _id: { $in: projectId.map(id => new ObjectId(id)) }
    }).toArray();

    res.status(200).json(projects);
  } catch (error) {
    console.error("Error finding projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


//-----------------> Read all projects for a specific user (public & founder) <-----------------//
router.get("/userprojects/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    const accessibleProjects = await projectCollection.find({
      $or: [
        { isVisible: 1 },
        { founderId: new ObjectId(userId) }
      ]
    }).toArray();

    res.status(200).json(accessibleProjects);
  } catch (error) {
    console.error("Error fetching user projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


//-----------------> Update Project <-----------------//
router.put("/projects/:id", async (req, res) => {
  const { id } = req.params;
  const updateFields = req.body;
  let error = "";

  if (!Object.keys(updateFields).length) {
    error = "No fields provided to update";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");

    // Convert any provided ObjectId fields
    if (updateFields.team) {
      updateFields.team = new ObjectId(updateFields.team);
    }
    if (updateFields.tasks) {
      updateFields.tasks = updateFields.tasks.map((id) => new ObjectId(id));
    }
    if (updateFields.founderId) {
      updateFields.founderId = new ObjectId(updateFields.founderId);
    }
    if (updateFields.group) {
      updateFields.group = new ObjectId(updateFields.group);
    }

    const result = await projectCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields },
    );
    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

//-----------------> Delete a project <-----------------//
Date.prototype.addDays = function(days) {
    var date = new Date(this.valueOf());
    date.setDate(date.getDate() + days);
    return date;
}

// Delete a project
router.delete("/projects/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");

    // Ensure TTL index exists
    await deletedProjectsCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    await deletedTasksCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    await deletedTeamsCollection.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 2592000,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    // Find the project to delete
    const project = await projectCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 1;
    project.dateMoved = new Date();
    project.metadata = { projectId: id }; // Example metadata, adjust as needed

    // Insert the project into the deleted_projects collection
    await deletedProjectsCollection.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await taskCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { taskId: task._id }
        }));
        await deletedTasksCollection.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection
        await taskCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await teamCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { teamId: team._id }
        };
        await deletedTeamsCollection.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await teamCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await projectCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({ message: "Project and associated data moved to deleted collections successfully" });
  } catch (error) {
    console.error("Error deleting project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// Wipe a project
router.delete("/wipeproject/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");
    const deleteAll = db.collection("VOID");

    // Ensure TTL index exists
    await deleteAll.createIndex(
      { "dateMoved": 1 },
      {
        expireAfterSeconds: 0,
        partialFilterExpression: { "flagDeletion": 1 }
      }
    );

    // Find the project to delete
    const project = await deletedProjectsCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 1;
    project.dateMoved = new Date();
    project.metadata = { projectId: id }; // Example metadata, adjust as needed

    // Insert the project into the deleted_projects collection
    await deleteAll.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await deletedTasksCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { taskId: task._id }
        }));
        await deleteAll.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection
        await deletedTasksCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await deletedTeamsCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
          flagDeletion: 1,
          dateMoved: new Date(),
          metadata: { teamId: team._id }
        };
        await deleteAll.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await deletedTeamsCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await deletedProjectsCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({ message: "Project and associated data have been wiped successfully" });
  } catch (error) {
    console.error("Error wiping project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// Forgot password
router.post('/forgot-password', async (req, res) => 
{
  const {email} = req.body;
  let error = '';
  

  try{

    const db = client.db('ganttify');
    const results = db.collection('userAccounts');
    const user = await results.findOne({email});


    if (user) {
      
      const secret = process.env.JWT_SECRET + user.password;
      const token = jwt.sign({email: user.email, id: user._id}, secret, {expiresIn: "2m",} );

      let link = `https://ganttify-5b581a9c8167.herokuapp.com/reset-password/${user._id}/${token}`;
     
      

      const transporter = nodeMailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL,
          pass: process.env.EMAIL_PASSWORD
        }
      });

      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Reset Your Ganttify Password',
        text: `Hello ${user.name},\n We recieved a request to reset your Ganttify password. Click the link to reset your password: ${link}`,
        html: `<p>Hello ${user.name},</p> <p>We recieved a request to reset your Ganttify password. Click the button to reset your password:\n</p> <a href="${link}" className="btn">Reset Password</a>`
      };


      transporter.sendMail(mailDetails, function (err, data) {
        if (err) {
          return res.status(500).json({ error: 'Error sending email' });
        } else {
          return res.status(200).json({ message: 'Password reset email sent' });
        }
      });
    } else {
      return res.status(404).json({ error: 'User with that email address does not exist.' });
    }


  } catch (error) {
    console.error('An error has occurred:', error);
    return res.status(500).json({ error });
  } 
});
  
router.get('/reset-password/:id/:token', async (req, res) => 
{

  const { id, token } = req.params;

  try {

    const objectId = new ObjectId(id);
  
    const db = client.db('ganttify');
    const results = db.collection('userAccounts');
    const user = await results.findOne({_id: objectId});


    if (user) {
      const secret = process.env.JWT_SECRET + user.password;
  
      try {

        jwt.verify(token, secret);
        res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
  
      } catch (error) {
        res.send("Not verified");
      }
    } 
  
    else{
      return res.status(404).send("User does not exist");
    }
  } catch(error) {
    console.error('Error during password reset verification:', error);
    res.status(400).send("Invalid ID format");
  }

});
  
router.post('/reset-password', async (req, res) => 
{
  const { id, password } = req.body;

  let error = '';

  try {
    const db = client.db('ganttify');
    const objectId = ObjectId.createFromHexString(id); 
    const userCollection = db.collection('userAccounts');
    const user = await userCollection.findOne({_id: objectId});


    if (user){
      const hashedPassword = await bcrypt.hash(password, 10);

      try {
        await userCollection.updateOne({_id: objectId}, {$set: {password: hashedPassword}});
        res.status(200).json({ message: "Password has been reset successfully" });
      } catch(error) {
        return res.json({status: "error", data: error})
      }

    } else {
      error = 'User not found';
      return res.status(400).json({ error });
    }

  } catch (error) {
    console.error('Error occured during password reset:', error);
    error = 'Internal server error';
    res.status(500).json({ error });
  } 
});

//////////////////////
// SEARCH ENDPOINTS //
//////////////////////

// -----------------> Search a specific user <-----------------//
router.get("/user/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const user = await userCollection.findOne(
      { _id: new ObjectId(userId) },
      { projection: { password: 0 } } // Exclude the password field
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error finding user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// -----------------> Get All Users <-----------------//
router.get("/allusers", async (req, res) => {
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Retrieve all users excluding their passwords
    const users = await userCollection.find({}, { projection: { password: 0 } }).toArray();
    
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//------------------> Search users by ids<-------------------------------------//
router.post("/search/taskworkers", async (req, res) => {
  const { ids } = req.body;
  //console.log(ids);
  const oIds = ids.map((id) => new ObjectId(id));
  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    const query = {_id : {$in : oIds}};

    // Find users matching ids excluding passwords
    const users = await userCollection.find(query).project({name:1,phone:1,email:1}).toArray();
    //console.log(users);
    res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------> Search users by email, name, username or projects <-----------------//
router.post("/searchusers", async (req, res) => {
  const { email, name, username, projects } = req.body;

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");

    // Build search criteria array
    const searchCriteria = [];
    if (email) searchCriteria.push({ email: email });
    if (name) searchCriteria.push({ name: name });
    if (username) searchCriteria.push({ username: username });
    if (projects && projects.length) {
      // Search for users where the projects field contains any of the given project IDs
      searchCriteria.push({ projects: { $in: projects.map(id => new ObjectId(id)) } });
    }

    // Check if there are any search criteria
    if (searchCriteria.length === 0) {
      return res.status(400).json({ error: "At least one search parameter must be provided" });
    }

    // Find users matching any of the search criteria, excluding passwords
    const users = await userCollection.find({
      $or: searchCriteria
    }, {
      projection: { password: 0 } // Exclude password from the results
    }).toArray();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-> Search Project by Title & Sort by Date Created <-//
router.post("/search/projects", async (req, res) => {

    const { founderId, title, sortBy = "dateCreated" } = req.body;
  
    try {
      const db = client.db("ganttify");
      const projectCollection = db.collection("projects");
      const teamCollection = db.collection("teams");
  
      const teams = await teamCollection.find({
        $or: [
          { founderId: new ObjectId(founderId) },
          { editors: new ObjectId(founderId) },
          { members: new ObjectId(founderId) }
        ]
      }).toArray();
  
     console.log("These are the teams: ", teams);
  
      const teamIds = teams.map(team => new ObjectId(team._id));
  
     console.log("These are the team IDs: ", teamIds);
  
      const query = {
        $or: [
          { founderId: new ObjectId(founderId) },
          { team: { $in: teamIds } }
        ],
        nameProject: { $regex: title, $options: "i" }
      };
  
      console.log("These are the query: ", query);
  
      const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending
  
      const projects = await projectCollection
        .find(query)
        .sort(sortOptions)
        .toArray();
  
      res.status(200).json(projects);
  
      console.log("These are the projects: ", projects);
  
    } catch (error) {
      console.error("Error searching projects:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }); 
  
//-> Search Recently-Deleted Projects by Title & Sort by Due Date <-//
router.post("/search/recently-deleted", async (req, res) => {

  const { founderId, title, sortBy = "dueDate" } = req.body;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("recently_deleted_projects");


    const query = {founderId: new ObjectId(founderId), nameProject: { $regex: title, $options: "i" } };

    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending

    const projects = await projectCollection
      .find(query)
      .sort(sortOptions)
      .toArray();

    res.status(200).json(projects);


  } catch (error) {
    console.error("Error searching projects:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}); 

//-> Search Categories by Title and Sort by Completion Percentage <-//
router.post("/search/categories", async (req, res) => {
  const { title, sortBy = "completionPercentage" } = req.body;

  try {
    const db = client.db("ganttify");
    const categoryCollection = db.collection("categories");

    const query = { title: { $regex: title, $options: "i" } };
    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending

    const categories = await categoryCollection
      .find(query)
      .sort(sortOptions)
      .toArray();

    res.status(200).json(categories);
  } catch (error) {
    console.error("Error searching categories:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Search Task by Name, Due Date, (Sort by Completion Percentage)
router.post("/search/tasks", async (req, res) => {
    //need to also add functionality for teamId, we'll get there
  const {founderId, name, dueDate, sortBy = "completionPercentage" } = req.body;
  const query = {};

  if (!dueDate) {
    query.description = { founderId:founderId,$regex: name, $options: "i" };
  }
  
  else {
    query.description = { founderId: founderId, $gte: new Date(dueDate) };
  }
  console.log(query);

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const sortOptions = { [sortBy]: 1 }; // 1 for ascending, -1 for descending

    const tasks = await taskCollection.find(query).sort(sortOptions).toArray();

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//-> Search Task for Specific User on Project Team <-//
router.post("/search/tasks/users", async (req, res) => {
  const { projectId, userId } = req.body;

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const query = {
      tiedProjectId: ObjectId(projectId),
      assignedTasksUsers: ObjectId(userId),
    };

    const tasks = await taskCollection.find(query).toArray();

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks for user on project team:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
//-> Search Tasks for Specific User  <-//
router.post("/search/tasks/todo", async (req, res) => {
    const { userId } = req.body;
  
    try {
      const db = client.db("ganttify");
      const taskCollection = db.collection("tasks");
  
      const query = {
        assignedTasksUsers: new ObjectId(userId),
      };
      
      const tasks = await taskCollection.find(query).sort({dueDateTime: 1}).toArray();
  
      res.status(200).json(tasks);
    } catch (error) {
      console.error("Error searching tasks for user on project team:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  //-------------> Display team info <-------------//
router.get('/teams/:teamId/teaminfo', async (req, res) => {
  const { teamId } = req.params;

  if (!teamId) {
    return res.status(400).json({ error: "Team ID is required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts"); // Changed from 'users' to 'userAccounts'

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }

    // Convert teamId to ObjectId
    const teamObjectId = new ObjectId(teamId);

    // Check if the team exists
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Retrieve the members and editors details
    const members = await userCollection.find({ _id: { $in: team.members } }).toArray();
    const editors = await userCollection.find({ _id: { $in: team.editors } }).toArray();

    return res.status(200).json({
      members: members.map(member => ({ id: member._id, name: member.name })),
      editors: editors.map(editor => ({ id: editor._id, name: editor.name }))
    });
  } catch (error) {
    console.error("Error retrieving team members and editors:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Restore a project
router.post("/restore-project/:id", async (req, res) => {
  const { id } = req.params;
  let error = "";

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");
    const teamCollection = db.collection("teams");
    const deletedProjectsCollection = db.collection("recently_deleted_projects");
    const deletedTasksCollection = db.collection("recently_deleted_tasks");
    const deletedTeamsCollection = db.collection("recently_deleted_teams");

    // Find the project to restore
    const project = await deletedProjectsCollection.findOne({ _id: new ObjectId(id) });
    console.log("Project data:", project); // Debugging line

    if (!project) {
      error = "Project not found";
      return res.status(404).json({ error });
    }

    // Set flagDeletion to 1, add dateMoved and metadata fields
    project.flagDeletion = 0;
    delete project.dateMoved;
    delete project.metadata; // Example metadata, adjust as needed

    // Insert the project into the deleted_projects collection
    await projectCollection.insertOne(project);

    // Handle associated tasks
    if (project.tasks && project.tasks.length > 0) {
      const taskIds = project.tasks.map(taskId => new ObjectId(taskId));
      console.log("Task IDs to move:", taskIds); // Debugging line
      const tasks = await deletedTasksCollection.find({ _id: { $in: taskIds } }).toArray();
      console.log("Tasks found:", tasks); // Debugging line
      if (tasks.length > 0) {
        // Set dateMoved and metadata for tasks
        const tasksToMove = tasks.map(task => ({
          ...task,
          flagDeletion: 0
        }));
        await taskCollection.insertMany(tasksToMove);
        console.log("Tasks moved to deleted_tasks"); // Debugging line
        // Delete the associated tasks from the main collection
        await deletedTasksCollection.deleteMany({ _id: { $in: taskIds } });
      } else {
        console.log("No tasks found for the project"); // Debugging line
      }
    } else {
      console.log("No tasks assigned to the project"); // Debugging line
    }

    // Handle associated team
    if (project.team) {
      const teamId = new ObjectId(project.team);
      console.log("Team ID to move:", teamId); // Debugging line
      const team = await deletedTeamsCollection.findOne({ _id: teamId });
      console.log("Team found:", team); // Debugging line
      if (team) {
        // Set dateMoved and metadata for the team
        const teamToMove = {
          ...team,
          flagDeletion: 0
        };
        await teamCollection.insertOne(teamToMove);
        console.log("Team moved to deleted_teams"); // Debugging line
        // Delete the associated team from the main collection
        await deletedTeamsCollection.deleteOne({ _id: teamId });
      } else {
        console.log("Team not found for the project"); // Debugging line
      }
    } else {
      console.log("No team assigned to the project"); // Debugging line
    }

    // Delete the project from the main collection
    await deletedProjectsCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({ message: "Project and associated data restored to collections successfully" });
  } catch (error) {
    console.error("Error restoring project:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});

// Add members to a team
router.put('/teams/:teamId/members', async (req, res) => {
  const { teamId } = req.params;
  const { members = [] } = req.body;

  if (!teamId) {
    return res.status(400).json({ error: "Team ID is required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }

    // Validate teamId
    if (!ObjectId.isValid(teamId)) {
      return res.status(400).json({ error: "Invalid Team ID format" });
    }
    
    // Convert teamId to ObjectId
    const teamObjectId = new ObjectId(teamId);

    // Check if the team exists
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Validate user IDs
    for (const id of members) {
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ error: `Invalid user ID format: ${id}` });
      }
    }

    // Convert user IDs to ObjectId
    const memberObjectIds = members.map(id => new ObjectId(id));

    // Verify that all members are valid users
    const users = await userCollection.find({ _id: { $in: memberObjectIds } }).toArray();
    const validUserIds = users.map(user => user._id.toString());

    const invalidMembers = members.filter(id => !validUserIds.includes(id));

    if (invalidMembers.length > 0) {
      return res.status(400).json({ error: "Some provided user IDs are invalid", invalidMembers });
    }

    // Update the team with new members
    const update = {
      $addToSet: {
        members: { $each: memberObjectIds }
      }
    };

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update team" });
    }

    return res.status(200).json({ message: "Members added successfully" });
  } catch (error) {
    console.error("Error updating team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});


// Update the role of an existing member
router.put('/teams/:teamId/update-role', async (req, res) => {


  const { teamId } = req.params;
  const { userId, newRole } = req.body;


  if (!teamId || !userId || !newRole) {
    return res.status(400).json({ error: "Team ID, user ID, and new role are required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

   
    if (!ObjectId.isValid(teamId) || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid Team ID or User ID format" });
    }

    const teamObjectId = new ObjectId(teamId);
    const userObjectId = new ObjectId(userId);

  
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    
    const user = await userCollection.findOne({ _id: userObjectId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMember = teamCollection.findOne({members: userObjectId});
    const isEditor = teamCollection.findOne({editors: userObjectId});
    


    if (!isMember && !isEditor) {
      return res.status(404).json({ error: "User not found in the team" });
    }

    let update;


    if (newRole === "editor") {
      update = {
        $addToSet: { editors: userObjectId },
        $pull: { members: userObjectId }
      };



    } else if (newRole === "member") {
      update = {
        $addToSet: { members: userObjectId },
        $pull: { editors: userObjectId }
      };
   

    } 
    
    else {
      return res.status(400).json({ error: "Invalid role. Role must be 'editor' or 'member'." });
    }

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update user's role in the team" });
    }

    return res.status(200).json({ message: "User's role updated successfully" });

  } catch (error) {
    console.error("Error updating user's role in the team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});



// Removes members or editors from a team
router.put('/teams/:teamId/removeteammember', async (req, res) => {

  const { teamId } = req.params;
  const { userId, projectId } = req.body;

  if (!teamId || !userId || !projectId) {
    return res.status(400).json({ error: "Team ID, User ID, and Project ID are required" });
  }

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const userCollection = db.collection("userAccounts");

   
    

    if (!ObjectId.isValid(teamId) || !ObjectId.isValid(userId) || !ObjectId.isValid(projectId)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const teamObjectId = new ObjectId(teamId);
    const userObjectId = new ObjectId(userId);
    const projectObjectId = new ObjectId(projectId);

 

   
    
    const team = await teamCollection.findOne({ _id: teamObjectId });
    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    const user = await userCollection.findOne({ _id: userObjectId });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

   
    const isMember = team.members.some(memberId => memberId.equals(userObjectId));
    const isEditor = team.editors.some(editorId => editorId.equals(userObjectId));

    console.log("Member: ", isMember, " , isEditor: ", isEditor);

    if (!isMember && !isEditor) {
      return res.status(404).json({ error: "User not found in the team" });
    }

 

    const update = {
      $pull: {
        members: userObjectId,
        editors: userObjectId
      }
    };

    const result = await teamCollection.updateOne({ _id: teamObjectId }, update);

    if (result.modifiedCount === 0) {
      return res.status(500).json({ error: "Failed to update team" });
    }

 
    const userUpdateResult = await userCollection.updateOne(
      { _id: userObjectId },
      { $pull: { projects: projectObjectId } }
    );

  

    return res.status(200).json({ message: "Member removed successfully" });
  } catch (error) {
    console.error("Error updating team:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});




router.post("/search/tasks/project", async (req, res) => {
  const { projectId } = req.body;

  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const taskCollection = db.collection("tasks");

    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    let tasks = [];

    if (Array.isArray(project.tasks) && project.tasks.length > 0) {
      tasks = await taskCollection.find({
        _id: { $in: project.tasks }
      }).toArray();
    }

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error searching tasks for project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/updateSingleUserToDoList", async (req, res) => {
  const { taskId, userId, isChecked } = req.body;
  let error = "";

  if (!taskId || !userId || typeof isChecked !== 'boolean') {
    error = "Task ID, user ID, and isChecked are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");


    await userCollection.updateOne({ _id: new ObjectId(userId) }, isChecked ? { $addToSet: { toDoList: new ObjectId(taskId) } } : { $pull: { toDoList: new ObjectId(taskId) } });

    res.status(200).json({ message: "User's toDoList updated successfully" });
  } catch (error) {

    
    console.error("Error updating user's toDoList:", error);
    error = "Internal server error";
    res.status(500).json({ error });
  }
});
router.get('/getProjectDetails/:projectId', async (req, res) => {
  const projectId = req.params.projectId;
  try {
    const db = client.db("ganttify");
    const projectCollection = db.collection("projects");
    const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    if (!project.team || !ObjectId.isValid(project.team)) {
      return res.status(404).json({ error: "Invalid team ID in project" });
    }

    

    const teamCollection = db.collection("teams");
    const team = await teamCollection.findOne({ _id: new ObjectId(project.team) });


    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    project.team = team;
    res.status(200).json(project);
  } catch (error) {
    console.error("Error fetching project:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get('/teams/:teamId', async (req, res) => {
  const teamId = req.params.teamId;

  try {
    const db = client.db("ganttify");
    const teamCollection = db.collection("teams");
    const team = await teamCollection.findOne({ _id: new ObjectId(teamId) });

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    res.status(200).json(team);
  } catch (error) {
    console.error("Error fetching team:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});






//Invite team member api's//

  router.post('/invite-user', async (req, res) => {
    const { email, projectId } = req.body;
  
    if (!email || !projectId) {
      return res.status(400).json({ error: 'Email and Project ID are required' });
    }
  
    try {
      const db = client.db('ganttify');
      const userAccounts = db.collection('userAccounts');
      const user = await userAccounts.findOne({ email });
  
      const secret = process.env.JWT_SECRET + (user ? user.password : 'newuseraccount');
      const token = jwt.sign({ email, projectId }, secret, { expiresIn: '5m' });
      
      const link = user ? `https://ganttify-5b581a9c8167.herokuapp.com/accept-invite/${token}` : `https://ganttify-5b581a9c8167.herokuapp.com/register/${token}`;
  
      const transporter = nodeMailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
  
      const mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Invitation to Join Ganttify',
        text: `Hello,\n\nYou have been invited to join a project on Ganttify. Click the link to ${user ? 'accept the invitation' : 'create an account and join'}: ${link}`,
        html: `<p>Hello,</p><p>You have been invited to join a project on Ganttify. Click the button below to ${user ? 'accept the invitation' : 'create an account and join'}:</p><a href="${link}" class="btn">Join Ganttify</a>`,
      };
  
      transporter.sendMail(mailDetails, (err, data) => {

        if (err) {
          return res.status(500).json({ error: 'Error sending email' });
        } else {
          return res.status(200).json({ message: 'Invitation email sent' });
        }

      });
    } catch (error) {
      console.error('Error inviting user:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
  



   router.get('/accept-invite/:token', async (req, res) => {
    const { token } = req.params;
  
    try {
      const decodedToken = jwt.decode(token);
      const { email, projectId } = decodedToken;
  
      const db = client.db('ganttify');
      const userAccounts = db.collection('userAccounts');
      const projectCollection = db.collection('projects');
      const teamCollection = db.collection('teams');
  
      const user = await userAccounts.findOne({ email });
  
      if (user) {
        const secret = process.env.JWT_SECRET + user.password;
  
        try {
          jwt.verify(token, secret);
  
          await userAccounts.updateOne(
            { _id: user._id },
            { $addToSet: { projects: new ObjectId(projectId) } }
          );
  
          const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });


          if (!project) {
            return res.status(404).send('Project does not exist');
          }
  
          await teamCollection.updateOne(
            { _id: new ObjectId(project.team) },
            { $addToSet: { members: user._id } }
          );
  

          res.sendFile(path.resolve(__dirname, 'frontend', 'build', 'index.html'));
        } catch (error) {
          console.error('Invalid or expired token:', error);
          res.status(400).send('Invalid or expired token');
        }
      } else {
        return res.status(404).send('User does not exist');
      }


    } catch (error) {
      console.error('Error during invitation acceptance:', error);
      res.status(400).send('Invalid ID format');
    }
  });



   router.post("/register/:token", async (req, res) => {


    const { token } = req.params;
    const { email, name, phone, password, username } = req.body;
  
    if (!email || !name || !phone || !password || !username) {
      return res.status(400).json({ error: "All fields are required" });
    }
  
    try {


      const decodedToken = jwt.decode(token);

      const { projectId } = decodedToken;
  
      const db = client.db("ganttify");
      const userCollection = db.collection("userAccounts");
  

      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Email already used" });
      }
  

      const hashedPassword = await bcrypt.hash(password, 10);
  
      const newUser = {
        email,
        name,
        phone,
        password: hashedPassword,
        username,
        accountCreated: new Date(),
        projects: [],
        toDoList: [],
        isEmailVerified: false,
      };
  
      // Insert the new user
      const insertedUser = await userCollection.insertOne(newUser);
  
      const secret = process.env.JWT_SECRET + hashedPassword;
      const verificationToken = jwt.sign({ email: newUser.email, projectId }, secret, { expiresIn: "5m" });
  
      let link = `https://ganttify-5b581a9c8167.herokuapp.com/verify-invite/${verificationToken}`;
  
      const transporter = nodeMailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL,
          pass: process.env.EMAIL_PASSWORD
        }
      });
  
      let mailDetails = {
        from: process.env.USER_EMAIL,
        to: email,
        subject: 'Verify Your Ganttify Account',
        text: `Hello ${newUser.name},\n Please verify your Ganttify account by clicking the following link: ${link}`,
        html: `<p>Hello ${newUser.name},</p> <p>Please verify your Ganttify account by clicking the following link:\n</p> <a href="${link}" className="btn">Verify Account</a>`
      };
  
      transporter.sendMail(mailDetails, function (err, data) {
        if (err) {
          return res.status(500).json({ error: 'Error sending verification email' });
        } else {
          return res.status(200).json({ message: 'Verification email sent' });
        }
      });
    } catch (error) {
      console.error('An error has occurred:', error);
      return res.status(500).json({ error });
    }
  });


router.post('/decode-token', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.email) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    res.json({ email: decoded.email });
  } catch (error) {
    console.error('Error decoding token:', error);
    res.status(500).json({ error: 'Failed to decode token' });
  }
});



router.get('/verify-invite/:token', async (req, res) => {
  const { token } = req.params;

  try {

    const decodedToken = jwt.decode(token);
    if (!decodedToken) {
      return res.status(400).send("Invalid token");
    }

    const { email, projectId } = decodedToken;


    const db = client.db("ganttify");
    const userCollection = db.collection("userAccounts");
    const projectCollection = db.collection("projects");
    const teamCollection = db.collection("teams");

    const user = await userCollection.findOne({ email });


    if (!user) {
      return res.status(404).send("User does not exist");
    }

    const secret = process.env.JWT_SECRET + user.password;


    try {
      jwt.verify(token, secret);


      await userCollection.updateOne(
        { _id: user._id },
        { $set: { isEmailVerified: true }, $addToSet: { projects: projectId } }
      );

      const project = await projectCollection.findOne({ _id: new ObjectId(projectId) });
      if (!project) {
        return res.status(404).send('Project does not exist');
      }

      await teamCollection.updateOne(
        { _id: new ObjectId(project.team) },
        { $addToSet: { members: user._id } }
      );


      return res.status(200).send("User verified and added to project and team");
    } catch (error) {
      console.error('Token verification failed:', error);
      return res.status(400).send("Invalid or expired token");
    }
  } catch (error) {
    console.error('Error during invitation acceptance:', error);
    return res.status(400).send("Invalid ID format");
  }
});

router.put("/tasks/:id/dates", async (req, res) => {

  const { id } = req.params;
  const { dueDateTime, startDateTime } = req.body;
  let error = "";

  if (!dueDateTime && !startDateTime) {
    error = "Both dueDateTime and startDateTime are required";
    return res.status(400).json({ error });
  }

  try {
    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");

    const updateFields = {};
    if (dueDateTime) {
      updateFields.dueDateTime = new Date(dueDateTime);
    }
    if (startDateTime) {
      updateFields.startDateTime = new Date(startDateTime);
    }

    const result = await taskCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields },
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating task dates:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});



router.get("/tasks/:id", async (req, res) => {


  const { id } = req.params;



  try {

    const db = client.db("ganttify");
    const taskCollection = db.collection("tasks");
    const task = await taskCollection.findOne({ _id: new ObjectId(id) });

    
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }


    res.status(200).json(task);

    
  } catch (error) {
    console.error("Error fetching task:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});





module.exports = router;
