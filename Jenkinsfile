@Library('libpipelines') _

hose {
    EMAIL = 'sysinternal@stratio.com'
    BUILDTOOL = 'docker'

    DEV = { config ->
            doDockers(conf: config, dockerImages: [[conf: config, dockerfile: 'Dockerfile', image: 'sysinternal-external-users-expired']])
    }
}
